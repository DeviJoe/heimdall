package main

import (
	"Heimdall/internal/agent/launcher"
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	c, err := launcher.Parse(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		slog.Error("agent configuration rejected", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if c.InternalClient {
		err = launcher.InternalNetwork(ctx)
	} else {
		err = launcher.Run(ctx, c)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}
