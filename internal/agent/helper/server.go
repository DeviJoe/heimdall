package helper

import (
	"Heimdall/internal/agent/activity"
	"Heimdall/internal/agent/native"
	"Heimdall/internal/synchronization"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

func Serve(ctx context.Context, socket, stateDir, publicKeyFile, authLog, joinToken string, agentUID int) error {
	return ServeWithIdentity(ctx, socket, stateDir, publicKeyFile, authLog, joinToken, agentUID, agentUID)
}
func ServeWithIdentity(ctx context.Context, socket, stateDir, publicKeyFile, authLog, joinToken string, agentUID, agentGID int) error {
	key, err := os.ReadFile(publicKeyFile)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("invalid state verification key")
	}
	executor, err := native.New(stateDir)
	if err != nil {
		return err
	}
	checkpoint, err := executor.Checkpoint()
	if err != nil {
		return err
	}
	bootstrap, err := loadBootstrap(stateDir, joinToken, checkpoint.NodeID != "")
	if err != nil {
		return err
	}
	telemetry, err := activity.New(authLog, filepath.Join(stateDir, "activity-journal.json"))
	if err != nil {
		return err
	}
	go telemetry.Run(ctx)
	if err = os.MkdirAll(filepath.Dir(socket), 0755); err != nil {
		return err
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("unsafe helper socket")
		}
		if err = os.Remove(socket); err != nil {
			return err
		}
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chown(socket, 0, agentGID); err != nil {
		return err
	}
	if err = os.Chmod(socket, 0660); err != nil {
		return err
	}
	var mutex sync.Mutex
	var healthMutex sync.RWMutex
	health := synchronization.AgentHealth{}
	recordHealth := func(err error) {
		healthMutex.Lock()
		defer healthMutex.Unlock()
		health.CheckedAt = time.Now().UTC()
		health.Error = ""
		if err != nil {
			health.Error = err.Error()
		}
	}
	err = executor.Recover(ctx)
	recordHealth(err)
	if err != nil {
		slog.Error("native account journal recovery incomplete", "error", err)
	}
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				mutex.Lock()
				err := executor.Reconcile(ctx)
				mutex.Unlock()
				recordHealth(err)
				if err != nil {
					slog.Error("local account drift reconciliation failed", "error", err)
				}
			}
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /bootstrap", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(bootstrap) })
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		healthMutex.RLock()
		current := health
		healthMutex.RUnlock()
		if problem := telemetry.Health(); problem != "" {
			current.Error += "; " + problem
		}
		json.NewEncoder(w).Encode(current)
	})
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		events, _ := telemetry.Batch()
		json.NewEncoder(w).Encode(events)
	})
	mux.HandleFunc("POST /events/ack", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		var ids []string
		if json.NewDecoder(r.Body).Decode(&ids) != nil {
			http.Error(w, "invalid acknowledgements", 400)
			return
		}
		if err := telemetry.Ack(ids); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /apply", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
		defer r.Body.Close()
		var signed synchronization.SignedState
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&signed); err != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		state, err := synchronization.VerifyState(key, signed)
		if err != nil {
			http.Error(w, err.Error(), 403)
			return
		}
		mutex.Lock()
		defer mutex.Unlock()
		checkpoint, err := executor.Checkpoint()
		if err != nil {
			http.Error(w, "checkpoint unavailable", 500)
			return
		}
		if err = bootstrap.verify(state, checkpoint.NodeID != ""); err != nil {
			http.Error(w, err.Error(), 403)
			return
		}
		result, err := executor.Apply(r.Context(), state, signed.Digest)
		localError := err
		if localError == nil && result.Error != "" {
			localError = errors.New(result.Error)
		}
		recordHealth(localError)
		if err != nil {
			http.Error(w, err.Error(), 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("GET /checkpoint", func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		c, err := executor.Checkpoint()
		if err != nil {
			http.Error(w, "checkpoint unavailable", 500)
			return
		}
		json.NewEncoder(w).Encode(c)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		if !peerAllowed(c, agentUID) {
			c.Close()
		}
		return ctx
	}}
	go func() { <-ctx.Done(); server.Close() }()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func Health(ctx context.Context, client *http.Client) synchronization.AgentHealth {
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	r, _ := http.NewRequestWithContext(bounded, "GET", "http://helper/health", nil)
	response, err := client.Do(r)
	if err != nil {
		return synchronization.AgentHealth{Error: "root helper health unavailable"}
	}
	defer response.Body.Close()
	var status synchronization.AgentHealth
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&status) != nil {
		status.Error = "invalid root helper health response"
	}
	if status.CheckedAt.IsZero() || time.Since(status.CheckedAt) > 2*time.Minute {
		status.Error = "local Linux reconciliation has stalled"
	}
	return status
}
func Client(socket string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}, Timeout: 5 * time.Minute}
}
func Checkpoint(ctx context.Context, client *http.Client) (native.Checkpoint, error) {
	var cp native.Checkpoint
	r, err := http.NewRequestWithContext(ctx, "GET", "http://helper/checkpoint", nil)
	if err != nil {
		return cp, err
	}
	response, err := client.Do(r)
	if err != nil {
		return cp, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return cp, errors.New("checkpoint unavailable")
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 16<<20)).Decode(&cp)
	return cp, err
}
