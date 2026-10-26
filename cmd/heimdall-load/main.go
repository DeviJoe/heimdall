package main

import (
	"Heimdall/api/gen/agentv1"
	"Heimdall/internal/authorization"
	"Heimdall/internal/platform/pki"
	"Heimdall/internal/platform/postgres"
	"Heimdall/internal/synchronization"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log/slog"
	mathrand "math/rand/v2"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type agent struct {
	id          string
	certificate tls.Certificate
}

func main() {
	if err := run(); err != nil {
		slog.Error("load test failed", "error", err)
		os.Exit(1)
	}
}
func run() error {
	count := flag.Int("agents", 20000, "independent TLS agents")
	hold := flag.Duration("hold", 45*time.Second, "hold all agents connected")
	address := flag.String("grpc", "load-controlplane:9443", "isolated gateway")
	dir := flag.String("pki", "/pki", "test signing authority")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	dsn := os.Getenv("HEIMDALL_DATABASE_DSN")
	conf, err := pgxpool.ParseConfig(dsn)
	if err != nil || conf.ConnConfig.Database != "linpam_load" {
		return errors.New("load fixtures require the isolated linpam_load database")
	}
	if *count < 1 || *count > 20000 {
		return errors.New("agents must be 1–20000")
	}
	store, err := postgres.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer store.Close()
	if err = store.Migrate(ctx); err != nil {
		return err
	}
	authority, err := pki.Load(*dir)
	if err != nil {
		return err
	}
	var groupID string
	err = store.Pool.QueryRow(ctx, "INSERT INTO server_groups(id,name) VALUES($1,'Synthetic load agents') ON CONFLICT(name) DO UPDATE SET name=excluded.name RETURNING id", uuid.NewString()).Scan(&groupID)
	if err != nil {
		return err
	}
	var revision int64
	if err = store.Pool.QueryRow(ctx, "SELECT revision FROM system_state").Scan(&revision); err != nil {
		return err
	}
	agents := make([]agent, *count)
	batch := &pgx.Batch{}
	for i := range agents {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "load"}}, key)
		if err != nil {
			return err
		}
		id := uuid.NewString()
		certificate, parsed, err := authority.Issue(id, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), time.Hour)
		if err != nil {
			return err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		pair, err := tls.X509KeyPair(certificate, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
		if err != nil {
			return err
		}
		agents[i] = agent{id, pair}
		batch.Queue("INSERT INTO nodes(id,name,group_id,desired_revision,cert_serial,cert_expires) VALUES($1,$2,$3,$4,$5,$6)", id, fmt.Sprintf("synthetic-%05d", i), groupID, revision, parsed.SerialNumber.String(), parsed.NotAfter)
		if batch.Len() >= 500 {
			if err = store.Pool.SendBatch(ctx, batch).Close(); err != nil {
				return err
			}
			batch = &pgx.Batch{}
			if i%2000 == 499 {
				slog.Info("load identities prepared", "count", i+1)
			}
		}
	}
	if batch.Len() > 0 {
		if err = store.Pool.SendBatch(ctx, batch).Close(); err != nil {
			return err
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(authority.Certificate)
	var connected, acked, failures atomic.Int64
	var wait sync.WaitGroup
	done := make(chan struct{})
	start := time.Now()
	for index, a := range agents {
		wait.Add(1)
		go func(a agent, initial int) {
			defer wait.Done()
			attempt := 0
			for ctx.Err() == nil {
				delay := time.Duration(initial)*12*time.Millisecond + time.Duration(mathrand.IntN(300))*time.Millisecond
				if attempt > 0 {
					delay = time.Duration(mathrand.IntN(1<<min(attempt, 7))) * time.Second
				}
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				attempt++
				connection, err := grpc.NewClient(*address, grpc.WithReadBufferSize(8192), grpc.WithWriteBufferSize(8192), grpc.WithSharedWriteBuffer(true), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: roots, Certificates: []tls.Certificate{a.certificate}, ServerName: "controlplane", MinVersion: tls.VersionTLS13})))
				if err != nil {
					failures.Add(1)
					continue
				}
				rpc := agentv1.NewAgentServiceClient(connection)
				callCtx, stop := context.WithCancel(ctx)
				stream, err := rpc.Connect(callCtx)
				if err == nil {
					err = stream.Send(&agentv1.AgentMessage{Body: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{Version: "synthetic-load"}}})
				}
				if err == nil {
					var state *agentv1.ServerMessage
					state, err = stream.Recv()
					if err == nil {
						manifest, verifyErr := synchronization.VerifyState(authority.SigningKey.Public().(ed25519.PublicKey), synchronization.SignedState{Payload: state.Payload, Signature: state.Signature, Digest: state.Digest})
						err = verifyErr
						if err == nil && len(manifest.Accounts) != 0 {
							err = fmt.Errorf("isolated load fixture unexpectedly contains Linux access")
						}
						if err == nil {
							body, _ := json.Marshal(synchronization.ApplyResult{Revision: manifest.Revision, Digest: state.Digest, Results: []synchronization.ResourceResult{}})
							err = stream.Send(&agentv1.AgentMessage{Body: &agentv1.AgentMessage_Result{Result: &agentv1.ApplyResult{Json: body}}})
						}
					}
				}
				if err != nil {
					failures.Add(1)
					stop()
					connection.Close()
					continue
				}
				connected.Add(1)
				acked.Add(1)
				outgoing := make(chan *agentv1.AgentMessage, 1)
				ended := make(chan error, 1)
				go func() {
					for {
						state, err := stream.Recv()
						if err != nil {
							select {
							case ended <- err:
							case <-callCtx.Done():
							}
							return
						}
						manifest, verifyErr := synchronization.VerifyState(authority.SigningKey.Public().(ed25519.PublicKey), synchronization.SignedState{Payload: state.Payload, Signature: state.Signature, Digest: state.Digest})
						if verifyErr != nil || len(manifest.Accounts) != 0 {
							select {
							case ended <- fmt.Errorf("invalid synthetic state"):
							case <-callCtx.Done():
							}
							return
						}
						body, _ := json.Marshal(synchronization.ApplyResult{Revision: manifest.Revision, Digest: state.Digest, Results: []synchronization.ResourceResult{}})
						select {
						case outgoing <- &agentv1.AgentMessage{Body: &agentv1.AgentMessage_Result{Result: &agentv1.ApplyResult{Json: body}}}:
						case <-callCtx.Done():
							return
						}
					}
				}()
				ticker := time.NewTicker(15 * time.Second)
				alive := true
				finish := false
				for alive {
					select {
					case <-ctx.Done():
						alive = false
						finish = true
					case <-done:
						alive = false
						finish = true
					case <-ended:
						alive = false
					case message := <-outgoing:
						if stream.Send(message) != nil {
							alive = false
						}
					case <-ticker.C:
						if stream.Send(&agentv1.AgentMessage{Body: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{LastLocalCheck: time.Now().Unix()}}}) != nil {
							alive = false
						}
					}
				}
				ticker.Stop()
				connected.Add(-1)
				stop()
				connection.Close()
				if finish {
					return
				}
				attempt = 1

			}
		}(a, index)
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for connected.Load() < int64(*count) {
		select {
		case <-ctx.Done():
			close(done)
			wait.Wait()
			return fmt.Errorf("capacity not reached: %d/%d, failures %d", acked.Load(), *count, failures.Load())
		case <-ticker.C:
			slog.Info("load progress", "connected", connected.Load(), "target", *count, "failures", failures.Load(), "elapsed", time.Since(start).Round(time.Second))
		}
	}
	timeToConnect := time.Since(start)
	var adminID string
	if err = store.Pool.QueryRow(ctx, "SELECT id FROM users WHERE login='admin'").Scan(&adminID); err != nil {
		return err
	}
	principal, err := store.Principal(ctx, adminID, "", "api")
	if err != nil {
		return err
	}
	wideStart := time.Now()
	operation, err := store.SaveRole(ctx, principal, authorization.Role{Name: "Synthetic broad resync", Permissions: []string{}, Sudo: []authorization.SudoRule{}})
	if err != nil {
		return err
	}
	var remaining int
	for {
		if err = store.Pool.QueryRow(ctx, "SELECT count(*) FROM sync_targets WHERE operation_id=$1 AND status<>'applied'", operation).Scan(&remaining); err != nil {
			return err
		}
		if remaining == 0 {
			break
		}
		select {
		case <-ctx.Done():
			close(done)
			wait.Wait()
			return fmt.Errorf("broad resync did not converge: %d", remaining)
		case <-time.After(time.Second):
		}
	}
	wideSeconds := time.Since(wideStart).Seconds()
	slog.Info("broad change confirmed", "agents", *count, "seconds", wideSeconds)

	slog.Info("all agents connected", "agents", *count, "duration", timeToConnect)
	timer := time.NewTimer(*hold)
	select {
	case <-ctx.Done():
		timer.Stop()
		close(done)
		wait.Wait()
		return ctx.Err()
	case <-timer.C:
	}
	var confirmed, healthy int
	err = store.Pool.QueryRow(ctx, "SELECT count(*) FILTER(WHERE applied_revision=desired_revision),count(*) FILTER(WHERE last_seen>now()-interval '30 seconds') FROM nodes WHERE group_id=$1", groupID).Scan(&confirmed, &healthy)
	report := map[string]any{"agents": *count, "simultaneous_tls_connections": connected.Load(), "confirmed_revisions": confirmed, "recent_heartbeats": healthy, "connection_seconds": timeToConnect.Seconds(), "wide_change_seconds": wideSeconds, "hold_seconds": hold.Seconds(), "grpc_endpoint": *address, "signed_manifests_verified": true, "failed_attempts": failures.Load(), "fixture": "isolated database, synthetic agents without Linux accounts"}
	json.NewEncoder(os.Stdout).Encode(report)
	close(done)
	wait.Wait()
	if err != nil {
		return err
	}
	if confirmed != *count || healthy != *count {
		return fmt.Errorf("not all agents acknowledged or maintained heartbeat")
	}
	return nil
}
