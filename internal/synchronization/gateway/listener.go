package gateway

import (
	"context"
	"golang.org/x/time/rate"
	"net"
)

// Admission before TLS limits the expensive part of a mass reconnect, as well as RPC admission.
type pacedListener struct {
	net.Listener
	ctx  context.Context
	rate *rate.Limiter
}

func PaceListener(ctx context.Context, listener net.Listener) net.Listener {
	return &pacedListener{listener, ctx, rate.NewLimiter(100, 200)}
}
func (l *pacedListener) Accept() (net.Conn, error) {
	if err := l.rate.Wait(l.ctx); err != nil {
		return nil, err
	}
	return l.Listener.Accept()
}
