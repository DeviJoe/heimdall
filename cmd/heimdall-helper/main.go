package main

import (
	"Heimdall/internal/agent/helper"
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	socket := flag.String("socket", "/run/linpam/helper.sock", "Unix socket")
	state := flag.String("state-dir", "/var/lib/heimdall-helper", "root checkpoint directory")
	key := flag.String("state-key", "/trust/state.pub", "state verification key")
	uid := flag.Int("agent-uid", 998, "allowed agent UID/GID")
	authLog := flag.String("auth-log", "/var/log/auth.log", "OpenSSH authentication log")
	joinEnv := flag.String("join-token-env", "HEIMDALL_JOIN_TOKEN", "root enrollment intent environment variable")
	flag.Parse()
	if os.Geteuid() != 0 {
		slog.Error("helper requires root")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := helper.Serve(ctx, *socket, *state, *key, *authLog, os.Getenv(*joinEnv), *uid); err != nil {
		slog.Error("helper stopped", "error", err)
		os.Exit(1)
	}
}
