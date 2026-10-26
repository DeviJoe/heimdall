package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// FleetEvents carries invalidations only. Resource data still passes normal
// paginated RBAC queries; subscribers cannot slow down synchronization.
type FleetEvents struct {
	mu        sync.Mutex
	listeners map[chan struct{}]struct{}
}

func (h *FleetEvents) Publish() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.listeners {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
func (h *FleetEvents) subscribe() (chan struct{}, func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.listeners == nil {
		h.listeners = map[chan struct{}]struct{}{}
	}
	ch := make(chan struct{}, 1)
	h.listeners[ch] = struct{}{}
	return ch, func() { h.mu.Lock(); delete(h.listeners, ch); h.mu.Unlock() }
}
func (s *Server) fleetEvents(w http.ResponseWriter, r *http.Request) {
	p := Principal(r.Context())
	if p.Restricted || p.TokenID != "" || !fleetReadable(p) {
		Fail(w, application.ErrForbidden)
		return
	}
	if s.FleetEvents == nil {
		JSON(w, 503, map[string]string{"error": "Поток событий недоступен"})
		return
	}
	ch, unsubscribe := s.FleetEvents.subscribe()
	defer unsubscribe()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	controller := http.NewResponseController(w)
	send := func(data string) bool {
		_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := fmt.Fprint(w, data); err != nil {
			return false
		}
		return controller.Flush() == nil
	}
	if !send(": connected\n\n") {
		return
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	// Reauthenticate on periodic reconnect, including changed roles/auth versions.
	lifetime := time.NewTimer(time.Minute)
	defer lifetime.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-lifetime.C:
			return
		case <-ticker.C:
			if !send(": keepalive\n\n") {
				return
			}
		case <-ch:
			if !send("event: fleet\ndata: changed\n\n") {
				return
			}
		}
	}
}

func fleetReadable(p authorization.Principal) bool {
	for _, b := range p.Bindings {
		if p.Allowed("nodes.read", b.GroupID) || p.Allowed("sync.read", b.GroupID) {
			return true
		}
	}
	return false
}
