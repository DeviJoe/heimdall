package gateway

import (
	"Heimdall/api/gen/agentv1"
	"Heimdall/internal/platform/pki"
	"Heimdall/internal/synchronization"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

type Repository interface {
	RecordActivity(context.Context, string, string, []synchronization.ActivityEvent) ([]string, error)
	ConnectNode(context.Context, string, string) (int64, error)
	SnapshotForAgent(context.Context, string, int64) (synchronization.Snapshot, error)
	ApplyResult(context.Context, string, int64, synchronization.ApplyResult) error
	CertificatePolicy(context.Context) (synchronization.CertificatePolicy, error)
	NodeCertificate(context.Context, string, string, string, time.Time, int64) error
	NodeAllowed(context.Context, string, string) bool
	TouchNodes(context.Context, []synchronization.AgentHealth) error
	PendingConnections(context.Context, []string) ([]string, error)
	ActiveConnections(context.Context, []string) (map[string]synchronization.ConnectionIdentity, error)
}
type connection struct {
	wake       chan struct{}
	cancel     context.CancelFunc
	generation int64
	serial     string
	touched    bool
	health     synchronization.AgentHealth
}
type Gateway struct {
	agentv1.UnimplementedAgentServiceServer
	repo              Repository
	authority         *pki.Authority
	mu                sync.Mutex
	connections       map[string]*connection
	builders          chan struct{}
	admission         *rate.Limiter
	ApplyTimeout      time.Duration
	ApplyTimeoutValue func() time.Duration
}

func New(repo Repository, a *pki.Authority) *Gateway {
	return &Gateway{repo: repo, authority: a, connections: map[string]*connection{}, builders: make(chan struct{}, 16), admission: rate.NewLimiter(100, 200), ApplyTimeout: 15 * time.Minute}
}
func certificate(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("peer missing")
	}
	t, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(t.State.VerifiedChains) == 0 || len(t.State.PeerCertificates) == 0 {
		return nil, errors.New("verified client certificate required")
	}
	return t.State.PeerCertificates[0], nil
}
func (g *Gateway) Connect(stream grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ServerMessage]) error {
	if !g.admission.Allow() {
		return status.Error(codes.ResourceExhausted, "reconnect admission limit")
	}
	cert, err := certificate(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, "certificate required")
	}
	nodeID := cert.Subject.CommonName
	generation, err := g.repo.ConnectNode(stream.Context(), nodeID, cert.SerialNumber.String())
	if err != nil {
		return status.Error(codes.Unauthenticated, "node identity inactive")
	}
	ctx, cancel := context.WithDeadline(stream.Context(), cert.NotAfter)
	defer cancel()
	c := &connection{wake: make(chan struct{}, 1), cancel: cancel, generation: generation, serial: cert.SerialNumber.String(), touched: true}
	g.mu.Lock()
	if old := g.connections[nodeID]; old != nil {
		old.cancel()
	}
	g.connections[nodeID] = c
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		if g.connections[nodeID] == c {
			delete(g.connections, nodeID)
		}
		g.mu.Unlock()
	}()
	failure := make(chan error, 2)
	received := make(chan *agentv1.AgentMessage, 1)
	go func() {
		for {
			m, e := stream.Recv()
			if e != nil {
				select {
				case failure <- e:
				case <-ctx.Done():
				}
				return
			}
			select {
			case received <- m:
			case <-ctx.Done():
				return
			}
		}
	}()
	var sentMu sync.Mutex
	type manifest struct {
		digest string
		users  map[string]string
		sentAt time.Time
	}
	sent := map[int64]manifest{}
	var acknowledged int64
	var rootRevision int64
	go func() {
		last := time.Time{}
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.wake:
			}
			if delay := time.Second - time.Since(last); delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return
				}
			}
			select {
			case g.builders <- struct{}{}:
			case <-ctx.Done():
				return
			}
			sentMu.Lock()
			busy := len(sent) > 0
			sentMu.Unlock()
			if busy {
				<-g.builders
				continue
			}
			sentMu.Lock()
			base := rootRevision
			sentMu.Unlock()
			state, e := g.repo.SnapshotForAgent(ctx, nodeID, base)
			if e != nil {
				<-g.builders
				slog.Error("snapshot failed", "node", nodeID, "error", e)
				continue
			}
			sentMu.Lock()
			same := state.Revision == acknowledged
			sentMu.Unlock()
			if same {
				<-g.builders
				continue
			}
			payload, e := json.Marshal(state)
			<-g.builders
			if e != nil || len(payload) > 16<<20 {
				select {
				case failure <- errors.New("snapshot exceeds limit"):
				case <-ctx.Done():
				}
				return
			}
			signature, digest := g.authority.Sign(payload)
			sentMu.Lock()
			users := map[string]string{}
			for _, a := range state.Accounts {
				users[a.User.ID] = a.User.Login
			}
			sent[state.Revision] = manifest{digest: digest, users: users, sentAt: time.Now()}
			sentMu.Unlock()
			if e = stream.Send(&agentv1.ServerMessage{Payload: payload, Signature: signature, Digest: digest}); e != nil {
				select {
				case failure <- e:
				case <-ctx.Done():
				}
				return
			}
			last = time.Now()
		}
	}()
	hello := false
	ackTimeout := g.ApplyTimeout
	if ackTimeout <= 0 {
		ackTimeout = 15 * time.Minute
	}
	ackCheck := time.NewTicker(min(30*time.Second, ackTimeout/2))
	defer ackCheck.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failure:
			return err
		case now := <-ackCheck.C:
			if g.ApplyTimeoutValue != nil {
				if configured := g.ApplyTimeoutValue(); configured > 0 {
					ackTimeout = configured
				}
			}
			sentMu.Lock()
			var overdue int64
			for revision, pending := range sent {
				if now.Sub(pending.sentAt) >= ackTimeout {
					overdue = revision
					break
				}
			}
			sentMu.Unlock()
			if overdue > 0 {
				slog.Error("agent acknowledgement timed out; reconnect required", "node", nodeID, "revision", overdue, "timeout", ackTimeout)
				return status.Error(codes.DeadlineExceeded, "apply acknowledgement timeout; reconnect to reconcile")
			}
		case m := <-received:
			g.mu.Lock()
			c.touched = true
			g.mu.Unlock()
			switch body := m.Body.(type) {
			case *agentv1.AgentMessage_Hello:
				if hello {
					return status.Error(codes.InvalidArgument, "duplicate hello")
				}
				if body.Hello.Revision < 0 {
					return status.Error(codes.InvalidArgument, "invalid checkpoint")
				}
				sentMu.Lock()
				rootRevision = body.Hello.Revision
				sentMu.Unlock()
				if err = validNodeInfo(body.Hello.NodeInfo); err != nil {
					return status.Error(codes.InvalidArgument, err.Error())
				}
				g.mu.Lock()
				applyNodeInfo(&c.health, body.Hello.NodeInfo)
				g.mu.Unlock()
				hello = true
				g.Wake(nodeID)
			case *agentv1.AgentMessage_Heartbeat:
				if !hello {
					return status.Error(codes.InvalidArgument, "hello required")
				}
				if len(body.Heartbeat.LocalError) > 2048 || body.Heartbeat.LastLocalCheck > time.Now().Add(time.Minute).Unix() {
					return status.Error(codes.InvalidArgument, "invalid local health")
				}
				g.mu.Lock()
				c.health.NodeID = nodeID
				c.health.Error = body.Heartbeat.LocalError
				c.health.CheckedAt = time.Unix(body.Heartbeat.LastLocalCheck, 0).UTC()
				applyNodeInfo(&c.health, body.Heartbeat.NodeInfo)
				g.mu.Unlock()
			case *agentv1.AgentMessage_Result:
				if !hello || len(body.Result.Json) > 4<<20 {
					return status.Error(codes.InvalidArgument, "invalid result")
				}
				var r synchronization.ApplyResult
				if err = json.Unmarshal(body.Result.Json, &r); err != nil {
					return status.Error(codes.InvalidArgument, "invalid result")
				}
				sentMu.Lock()
				expected, exists := sent[r.Revision]
				sentMu.Unlock()
				if !exists || expected.digest != r.Digest {
					return status.Error(codes.InvalidArgument, "unexpected revision or digest")
				}
				seen := map[string]bool{}
				failed := false
				for _, resource := range r.Results {
					if seen[resource.UserID] || expected.users[resource.UserID] != resource.Login || (resource.Status != "applied" && resource.Status != "failed") {
						return status.Error(codes.InvalidArgument, "invalid resource acknowledgement")
					}
					seen[resource.UserID] = true
					failed = failed || resource.Status == "failed"
				}
				if len(seen) != len(expected.users) || (failed && r.Error == "") {
					return status.Error(codes.InvalidArgument, "incomplete acknowledgement")
				}
				if err = g.repo.ApplyResult(ctx, nodeID, generation, r); err != nil {
					slog.Warn("apply result rejected", "node", nodeID, "error", err)
				}
				sentMu.Lock()
				delete(sent, r.Revision)
				if r.Error == "" {
					rootRevision = r.Revision
				}
				if err == nil && r.Error == "" {
					acknowledged = r.Revision
				}
				sentMu.Unlock()
			default:
				return status.Error(codes.InvalidArgument, "unknown message")
			}
		}
	}
}
func (g *Gateway) Renew(ctx context.Context, r *agentv1.RenewRequest) (*agentv1.RenewResponse, error) {
	cert, err := certificate(ctx)
	if err != nil || !g.repo.NodeAllowed(ctx, cert.Subject.CommonName, cert.SerialNumber.String()) {
		return nil, status.Error(codes.Unauthenticated, "node inactive")
	}
	policy, err := g.repo.CertificatePolicy(ctx)
	if err != nil || !policy.Valid() {
		return nil, status.Error(codes.Unavailable, "certificate policy unavailable")
	}
	pem, next, err := g.authority.Issue(cert.Subject.CommonName, r.Csr, time.Duration(policy.TTLSeconds)*time.Second)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid CSR")
	}
	if err = g.repo.NodeCertificate(ctx, cert.Subject.CommonName, cert.SerialNumber.String(), next.SerialNumber.String(), next.NotAfter, policy.Version); err != nil {
		return nil, status.Error(codes.Unavailable, "renewal unavailable")
	}
	return &agentv1.RenewResponse{Certificate: pem, PolicyVersion: policy.Version, CaCertificate: g.authority.PublicCertificate()}, nil
}
func (g *Gateway) Wake(id string) {
	g.mu.Lock()
	c := g.connections[id]
	g.mu.Unlock()
	if c != nil {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
}
func (g *Gateway) ConnectionCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.connections)
}
func (g *Gateway) Run(ctx context.Context) {
	dispatch := time.NewTicker(5 * time.Second)
	heartbeat := time.NewTicker(10 * time.Second)
	defer dispatch.Stop()
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			g.mu.Lock()
			for _, c := range g.connections {
				c.cancel()
			}
			g.mu.Unlock()
			return
		case <-dispatch.C:
			if err := g.DispatchPending(ctx); err != nil {
				slog.Error("pending state dispatch failed", "error", err)
			}

		case <-heartbeat.C:
			ids := []synchronization.AgentHealth{}
			all := []string{}
			captured := map[string]*connection{}
			g.mu.Lock()
			for id, c := range g.connections {
				all = append(all, id)
				captured[id] = c
				if c.touched {
					v := c.health
					v.NodeID = id
					ids = append(ids, v)
					c.touched = false
				}
			}
			g.mu.Unlock()
			active, err := g.repo.ActiveConnections(ctx, all)
			if err != nil {
				slog.Error("connection fencing query failed", "error", err)
			} else {
				g.fence(captured, active)
			}
			if err := g.repo.TouchNodes(ctx, ids); err != nil {
				slog.Error("heartbeat persistence failed", "error", err)
			}
		}
	}
}

func (g *Gateway) DispatchPending(ctx context.Context) error {
	g.mu.Lock()
	all := make([]string, 0, len(g.connections))
	for id := range g.connections {
		all = append(all, id)
	}
	g.mu.Unlock()
	ids, err := g.repo.PendingConnections(ctx, all)
	if err != nil {
		return err
	}
	for _, id := range ids {
		g.Wake(id)
	}
	return nil
}

// Only fence the exact connections captured before the database read. A replacement
// arriving during that read belongs to a newer generation and must be left alone.
func (g *Gateway) fence(captured map[string]*connection, active map[string]synchronization.ConnectionIdentity) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, c := range captured {
		if g.connections[id] != c {
			continue
		}
		v, ok := active[id]
		if !ok || v.Generation != c.generation || v.Serial != c.serial {
			c.cancel()
		}
	}
}

func (g *Gateway) ReportActivity(ctx context.Context, request *agentv1.ActivityRequest) (*agentv1.ActivityResponse, error) {
	cert, err := certificate(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "verified node certificate required")
	}
	if len(request.Json) > 65536 {
		return nil, status.Error(codes.InvalidArgument, "activity payload too large")
	}
	var events []synchronization.ActivityEvent
	if err = json.Unmarshal(request.Json, &events); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid activity payload")
	}
	ids, err := g.repo.RecordActivity(ctx, cert.Subject.CommonName, cert.SerialNumber.String(), events)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "security activity was not persisted")
	}
	return &agentv1.ActivityResponse{AcknowledgedIds: ids}, nil
}

func validNodeInfo(info *agentv1.NodeInfo) error {
	if info == nil {
		return nil
	}
	if len(info.Hostname) > 253 || strings.ContainsAny(info.Hostname, "\x00\r\n") || len(info.Addresses) > 32 || len(info.Platform) > 32 {
		return errors.New("invalid node metadata")
	}
	for _, a := range info.Addresses {
		if net.ParseIP(a) == nil {
			return errors.New("invalid node address")
		}
	}
	return nil
}
func applyNodeInfo(health *synchronization.AgentHealth, info *agentv1.NodeInfo) {
	if info != nil {
		health.Hostname = info.Hostname
		health.Addresses = info.Addresses
		health.Platform = info.Platform
	}
}
