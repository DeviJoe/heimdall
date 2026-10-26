package client

import (
	"Heimdall/api/gen/agentv1"
	"Heimdall/internal/agent/helper"
	"Heimdall/internal/agent/native"
	"Heimdall/internal/synchronization"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"io"
	"log/slog"
	mathrand "math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	API, GRPC, ServerName, Name, JoinToken, RecoveryToken, Directory, CAFile, Socket string
	Heartbeat                                                                        time.Duration
}
type identity struct {
	PolicyVersion  int64  `json:"certificate_policy_version,omitempty"`
	RenewRequested bool   `json:"renew_requested,omitempty"`
	NodeID         string `json:"node_id"`
	Certificate    []byte `json:"certificate"`
	Key            []byte `json:"key"`
}

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Stable per-node spreading keeps a fleet enrolled together from renewing at
// once. Heartbeats also check this wall-clock deadline after host suspend or
// a clock correction; a monotonic timer alone can miss the certificate window.
func renewalDeadline(notAfter time.Time, nodeID string) time.Time {
	hash := sha256.Sum256([]byte(nodeID))
	spread := time.Duration(uint16(hash[0])<<8|uint16(hash[1])) * time.Hour / 65536
	return notAfter.Add(-8*time.Hour + spread)
}
func csr(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "join"}}, key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), err
}
func pool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(data) {
		return nil, errors.New("invalid CA")
	}
	return p, nil
}
func load(ctx context.Context, c Config) (identity, error) {
	var id identity
	path := filepath.Join(c.Directory, "identity.json")
	data, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(data, &id)
		return id, err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return id, err
	}
	if c.JoinToken == "" {
		return id, errors.New("initial enrollment requires a join token")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return id, err
	}
	request, err := csr(key)
	if err != nil {
		return id, err
	}
	roots, err := trustedPool(c)
	if err != nil {
		return id, err
	}
	bootstrapRequest, _ := http.NewRequestWithContext(ctx, "GET", "http://helper/bootstrap", nil)
	bootstrapResponse, err := helper.Client(c.Socket).Do(bootstrapRequest)
	if err != nil {
		return id, err
	}
	var bootstrap helper.Bootstrap
	err = json.NewDecoder(io.LimitReader(bootstrapResponse.Body, 4096)).Decode(&bootstrap)
	bootstrapResponse.Body.Close()
	if bootstrapResponse.StatusCode != 200 || err != nil || bootstrap.Nonce == "" {
		return id, errors.New("root enrollment binding unavailable")
	}
	body, _ := json.Marshal(map[string]any{"token": c.JoinToken, "name": c.Name, "csr": request, "bootstrap_nonce": bootstrap.Nonce})
	req, err := http.NewRequestWithContext(ctx, "POST", c.API+"/api/v1/agent/join", bytes.NewReader(body))
	if err != nil {
		return id, err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: c.ServerName, MinVersion: tls.VersionTLS13}}, Timeout: 20 * time.Second}
	defer hc.CloseIdleConnections()
	resp, err := hc.Do(req)
	if err != nil {
		return id, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return id, fmt.Errorf("enrollment refused: HTTP %d", resp.StatusCode)
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&id); err != nil {
		return id, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return id, err
	}
	id.Key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err = save(c, id); err != nil {
		return id, err
	}
	return id, nil
}
func save(c Config, id identity) error {
	if err := os.MkdirAll(c.Directory, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(id)
	if err != nil {
		return err
	}
	return native.AtomicWrite(filepath.Join(c.Directory, "identity.json"), data, 0600)
}
func Run(ctx context.Context, c Config) error {
	if c.Heartbeat <= 0 {
		c.Heartbeat = 30 * time.Second
	}
	attempt := 0
	for ctx.Err() == nil {
		started := time.Now()
		id, err := load(ctx, c)
		if err == nil {
			err = connect(ctx, c, id)
		}
		if ctx.Err() != nil {
			return nil
		}
		slog.Warn("agent connection ended; local accounts remain intact", "error", err)
		if time.Since(started) > time.Minute {
			attempt = 0
		}
		cap := time.Second << min(attempt, 8)
		if cap > 5*time.Minute {
			cap = 5 * time.Minute
		}
		attempt++
		if err = wait(ctx, time.Second+time.Duration(mathrand.Int64N(int64(cap)))); err != nil {
			return nil
		}
	}
	return nil
}
func connect(ctx context.Context, c Config, id identity) error {
	roots, err := trustedPool(c)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(id.Certificate, id.Key)
	if err != nil {
		return err
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	if parsed.Subject.CommonName != id.NodeID {
		return errors.New("certificate node identity mismatch")
	}
	if time.Now().After(parsed.NotAfter) {
		if c.RecoveryToken == "" {
			return errors.New("transport certificate expired; Linux access is intact; obtain a node recovery token")
		}
		return recoverIdentity(ctx, c, id, roots)
	}
	conn, err := grpc.NewClient(c.GRPC, grpc.WithReadBufferSize(8192), grpc.WithWriteBufferSize(8192), grpc.WithSharedWriteBuffer(true), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: c.ServerName, MinVersion: tls.VersionTLS13})), grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: time.Minute, Timeout: 20 * time.Second}), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(32<<20)))
	if err != nil {
		return err
	}
	defer conn.Close()
	rpc := agentv1.NewAgentServiceClient(conn)
	// Renew before starting a stream so the old serial is never used after replacement.
	renewAt := renewalDeadline(parsed.NotAfter, id.NodeID)
	if id.RenewRequested || !time.Now().Before(renewAt) {
		keyBlock, _ := pem.Decode(id.Key)
		if keyBlock == nil {
			return errors.New("invalid node key")
		}
		k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}
		key, ok := k.(ed25519.PrivateKey)
		if !ok {
			return errors.New("invalid node key type")
		}
		request, err := csr(key)
		if err != nil {
			return err
		}
		renewCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		response, err := rpc.Renew(renewCtx, &agentv1.RenewRequest{Csr: request})
		cancel()
		if err != nil {
			return err
		}
		if response.PolicyVersion <= 0 {
			return errors.New("invalid certificate policy version")
		}
		if err = acceptCertificate(c, id, response.Certificate, response.CaCertificate); err != nil {
			return err
		}
		id.Certificate = response.Certificate
		id.PolicyVersion = response.PolicyVersion
		id.RenewRequested = false
		if err = save(c, id); err != nil {
			return err
		}
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := rpc.Connect(ctx)
	if err != nil {
		return err
	}
	hc := helper.Client(c.Socket)
	go reportActivity(ctx, rpc, hc)
	cp, err := helper.Checkpoint(ctx, hc)
	if err != nil {
		return err
	}
	if cp.NodeID != "" && cp.NodeID != id.NodeID {
		return errors.New("helper checkpoint belongs to another node")
	}
	if err = stream.Send(&agentv1.AgentMessage{Body: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{Revision: cp.Revision, Digest: cp.Digest, Version: "0.1.0", NodeInfo: nodeInfo()}}}); err != nil {
		return err
	}
	type appliedMessage struct {
		message       *agentv1.AgentMessage
		policyVersion int64
	}
	results := make(chan appliedMessage, 1)
	fail := make(chan error, 2)
	states := make(chan *agentv1.ServerMessage, 1)
	go func() {
		for {
			state, err := stream.Recv()
			if err != nil {
				select {
				case fail <- err:
				case <-ctx.Done():
				}
				return
			}
			select {
			case states <- state:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case state := <-states:
				var manifest synchronization.Snapshot
				if json.Unmarshal(state.Payload, &manifest) != nil || manifest.NodeID != id.NodeID {
					select {
					case fail <- errors.New("state targets another node"):
					case <-ctx.Done():
					}
					return
				}
				signed := synchronization.SignedState{Payload: state.Payload, Signature: state.Signature, Digest: state.Digest}
				body, _ := json.Marshal(signed)
				req, err := http.NewRequestWithContext(ctx, "POST", "http://helper/apply", bytes.NewReader(body))
				if err != nil {
					return
				}
				response, err := hc.Do(req)
				var result synchronization.ApplyResult
				if err == nil {
					if response.StatusCode == 200 {
						err = json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&result)
					} else {
						detail, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
						err = fmt.Errorf("helper: %s", detail)
					}
					response.Body.Close()
				}
				if err != nil {
					result = synchronization.ApplyResult{Revision: manifest.Revision, Digest: state.Digest, Error: err.Error(), Results: []synchronization.ResourceResult{}}
					for _, a := range manifest.Accounts {
						result.Results = append(result.Results, synchronization.ResourceResult{UserID: a.User.ID, Login: a.User.Login, Status: "failed", Error: err.Error()})
					}
				}
				b, _ := json.Marshal(result)
				policyVersion := int64(0)
				if result.Error == "" {
					policyVersion = manifest.CertificatePolicy.Version
				}
				select {
				case results <- appliedMessage{message: &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Result{Result: &agentv1.ApplyResult{Json: b}}}, policyVersion: policyVersion}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	ticker := time.NewTicker(c.Heartbeat)
	defer ticker.Stop()
	renew := time.NewTimer(time.Until(renewAt))
	defer renew.Stop()
	// One stream writer; heartbeats continue while the root helper applies a snapshot.
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-fail:
			return err
		case <-renew.C:
			return nil
		case result := <-results:
			if err = stream.Send(result.message); err != nil {
				return err
			}
			if result.policyVersion > id.PolicyVersion {
				id.RenewRequested = true
				if err = save(c, id); err != nil {
					return err
				}
				return nil
			}
		case <-ticker.C:
			if !time.Now().Before(renewAt) {
				return nil
			}
			local := helper.Health(ctx, hc)
			if err = stream.Send(&agentv1.AgentMessage{Body: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{Revision: cp.Revision, LocalError: local.Error, LastLocalCheck: local.CheckedAt.Unix(), NodeInfo: nodeInfo()}}}); err != nil {
				return err
			}
		}
	}
}
