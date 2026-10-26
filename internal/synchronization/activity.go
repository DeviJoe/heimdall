package synchronization

import "time"

type ActivityEvent struct {
	ID         string    `json:"id"`
	NodeID     string    `json:"node_id,omitempty"`
	Login      string    `json:"login"`
	Address    string    `json:"address"`
	Kind       string    `json:"kind"`
	Severity   string    `json:"severity"`
	ObservedAt time.Time `json:"observed_at"`
}
