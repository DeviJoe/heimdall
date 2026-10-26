package httpapi

import (
	"Heimdall/internal/synchronization"
	"github.com/google/uuid"
	"net/http"
	"time"
)

func (s *Server) recoverNode(w http.ResponseWriter, r *http.Request) {
	if !s.join.Allow() {
		JSON(w, 429, nil)
		return
	}
	var v struct {
		NodeID string `json:"node_id"`
		Token  string `json:"token"`
		CSR    []byte `json:"csr"`
	}
	if !Decode(w, r, &v) {
		return
	}
	if _, err := uuid.Parse(v.NodeID); err != nil {
		JSON(w, 400, nil)
		return
	}
	settings, err := s.Store.Settings(r.Context())
	if err != nil {
		Fail(w, err)
		return
	}
	ttl := settings.NodeCertificateTTLSeconds
	if ttl == 0 {
		ttl = synchronization.DefaultNodeCertificateTTLSeconds
	}
	certificate, parsed, err := s.Authority.Issue(v.NodeID, v.CSR, time.Duration(ttl)*time.Second)
	if err != nil {
		JSON(w, 400, nil)
		return
	}
	if err = s.Store.RecoverNode(r.Context(), v.NodeID, v.Token, parsed.SerialNumber.String(), parsed.NotAfter); err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 201, map[string]any{"node_id": v.NodeID, "certificate": certificate})
}
