package postgres

import (
	"Heimdall/internal/synchronization"
	"context"
)

type ConnectionIdentity = synchronization.ConnectionIdentity

func (s *Store) ActiveConnections(ctx context.Context, ids []string) (map[string]ConnectionIdentity, error) {
	rows, err := s.Pool.Query(ctx, "SELECT id,generation,cert_serial,cert_expires FROM nodes WHERE id=ANY($1::uuid[]) AND NOT disabled AND cert_expires>now()", ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ConnectionIdentity{}
	for rows.Next() {
		var id string
		var v ConnectionIdentity
		if err = rows.Scan(&id, &v.Generation, &v.Serial, &v.Expires); err != nil {
			return nil, err
		}
		out[id] = v
	}
	return out, rows.Err()
}
