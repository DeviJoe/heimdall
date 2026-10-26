package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"time"
)

// One database listener per control plane, independently of browser count.
func (s *Store) RunFleetNotifications(ctx context.Context, publish func()) {
	for ctx.Err() == nil {
		conn, err := pgx.ConnectConfig(ctx, s.Pool.Config().ConnConfig.Copy())
		if err == nil {
			_, err = conn.Exec(ctx, "LISTEN heimdall_fleet")
			if err == nil {
				publish()
				for ctx.Err() == nil {
					_, err = conn.WaitForNotification(ctx)
					if err != nil {
						break
					}
					publish()
				}
			}
			closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = conn.Close(closeCtx)
			cancel()
		}
		if ctx.Err() != nil {
			return
		}
		slog.Warn("fleet event listener reconnecting", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}
