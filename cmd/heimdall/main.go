package main

import (
	"Heimdall/api/gen/agentv1"
	"Heimdall/internal/application"
	"Heimdall/internal/integrations"
	"Heimdall/internal/platform/config"
	"Heimdall/internal/platform/metrics"
	"Heimdall/internal/platform/pki"
	"Heimdall/internal/platform/postgres"
	"Heimdall/internal/platform/security"
	"Heimdall/internal/synchronization/gateway"
	"Heimdall/internal/synchronization/queue"
	"Heimdall/internal/transport/httpapi"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("Heimdall stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		return initialize(os.Args[2:])
	}
	path := flag.String("config", "config/controlplane.yaml", "YAML configuration")
	flag.Parse()
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	authority, err := pki.Load(c.Server.PKIDir)
	if err != nil {
		return err
	}
	store, err := postgres.New(ctx, os.Getenv(c.Database.DSNEnv))
	if err != nil {
		return err
	}
	defer store.Close()
	if err = store.Migrate(ctx); err != nil {
		return err
	}
	if err = store.Bootstrap(ctx, os.Getenv(c.Security.AdminPasswordEnv), os.Getenv(c.Security.JoinTokenEnv)); err != nil {
		return err
	}
	if err = store.SeedDocumentation(ctx); err != nil {
		return err
	}
	if err = store.InitSettings(ctx, application.Settings{ApplyTimeoutSeconds: int(c.Sync.ApplyTimeout.Seconds()), KeyWarnSeconds: 7 * 86400, KeyTTLSeconds: int(c.Security.KeyTTL.Seconds()), RequireSK: c.Security.RequireSK, StalledSeconds: int(c.Sync.Stalled.Seconds()), OfflineSeconds: int(c.Sync.Offline.Seconds()), RevocationAlertSeconds: int(c.Sync.RevocationAlert.Seconds()), SwaggerEnabled: c.Swagger.Enabled, MCPEnabled: c.MCP.Enabled}); err != nil {
		return err
	}
	redisOptions, err := redis.ParseURL(os.Getenv(c.Redis.URLEnv))
	if err != nil {
		return err
	}
	cache := redis.NewClient(redisOptions)
	defer cache.Close()
	if err = cache.Ping(ctx).Err(); err != nil {
		return err
	}
	cipher, err := security.NewCipher(os.Getenv(c.Security.EncryptionKeyEnv))
	if err != nil {
		return err
	}
	api, err := httpapi.New(store, cache, c, authority, cipher)
	if err != nil {
		return err
	}
	gatewayServer := gateway.New(store, authority)
	gatewayServer.ApplyTimeout = c.Sync.ApplyTimeout
	grpcTLS, err := authority.TLS(true)
	if err != nil {
		return err
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(grpcTLS)), grpc.ReadBufferSize(8192), grpc.WriteBufferSize(8192), grpc.SharedWriteBuffer(true), grpc.MaxRecvMsgSize(8<<20), grpc.MaxSendMsgSize(32<<20), grpc.KeepaliveParams(keepalive.ServerParameters{Time: 2 * time.Minute, Timeout: 30 * time.Second, MaxConnectionAge: 6 * time.Hour, MaxConnectionAgeGrace: time.Minute}), grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: time.Minute}))
	agentv1.RegisterAgentServiceServer(grpcServer, gatewayServer)
	listener, err := net.Listen("tcp", c.Server.GRPCListen)
	if err != nil {
		return err
	}
	defer listener.Close()
	apiTLS, err := authority.TLS(false)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: c.Server.APIListen, Handler: api.Handler(), TLSConfig: apiTLS, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	monitor := metrics.New(store, c)
	gatewayServer.ApplyTimeoutValue = monitor.ApplyTimeout
	api.FleetEvents = &httpapi.FleetEvents{}
	monitor.FleetChanged = api.FleetEvents.Publish
	go store.RunFleetNotifications(ctx, api.FleetEvents.Publish)
	monitor.ConnectionCount = gatewayServer.ConnectionCount
	if c.Queue.URLEnv != "" && os.Getenv(c.Queue.URLEnv) != "" {
		broker := &queue.Queue{URL: os.Getenv(c.Queue.URLEnv), Store: store, Wake: gatewayServer.DispatchPending}
		monitor.QueueConnected = broker.Connected
		go broker.Run(ctx)
	}
	failure := make(chan error, 3)
	go gatewayServer.Run(ctx)
	go monitor.Run(ctx)
	go (&integrations.Worker{Store: store, Config: c}).Run(ctx)
	go func() { failure <- grpcServer.Serve(gateway.PaceListener(ctx, listener)) }()
	go func() { failure <- server.ListenAndServeTLS("", "") }()
	var metricServer *http.Server
	if c.Metrics.Listen != "" {
		metricServer = &http.Server{Addr: c.Metrics.Listen, Handler: monitor.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
		if c.Metrics.TLS {
			metricServer.TLSConfig, err = authority.TLS(false)
			if err != nil {
				return err
			}
			if c.Metrics.MTLS {
				data, err := os.ReadFile(c.Metrics.ClientCAFile)
				if err != nil {
					return err
				}
				pool := x509.NewCertPool()
				if !pool.AppendCertsFromPEM(data) {
					return errors.New("invalid metrics client CA")
				}
				metricServer.TLSConfig.ClientCAs = pool
				metricServer.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
			}
			go func() { failure <- metricServer.ListenAndServeTLS("", "") }()
		} else {
			go func() { failure <- metricServer.ListenAndServe() }()
		}
	}
	slog.Info("Heimdall ready", "api", c.Server.APIListen, "grpc", c.Server.GRPCListen, "public_url", c.Server.PublicURL)
	select {
	case <-ctx.Done():
	case err = <-failure:
		stop()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdown)
	if metricServer != nil {
		metricServer.Shutdown(shutdown)
	}
	grpcServer.Stop()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func initialize(args []string) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := flags.String("dir", "/pki", "private PKI directory")
	public := flags.String("public", "/trust", "public verification directory")
	uid := flags.Int("uid", 10001, "control plane UID/GID")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := pki.Init(*dir); err != nil {
		return err
	}
	if _, err := pki.Load(*dir); err != nil {
		return err
	}
	if err := os.MkdirAll(*public, 0755); err != nil {
		return err
	}
	if err := os.Chmod(*public, 0755); err != nil {
		return err
	}
	for _, name := range []string{"ca.pem", "state.pub"} {
		data, err := os.ReadFile(filepath.Join(*dir, name))
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(*public, name), data, 0644); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err = os.Chown(filepath.Join(*dir, entry.Name()), *uid, *uid); err != nil {
			return err
		}
	}
	if err = os.Chown(*dir, *uid, *uid); err != nil {
		return err
	}
	fmt.Println("PKI initialized; nodes receive public trust anchors only")
	return nil
}
