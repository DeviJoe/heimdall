package postgres

import "context"

// Hold row locks through publisher confirmation. A crash rolls back the checkpoint
// and duplicates a wakeup; coalescing and desired revisions make that harmless.
func (s *Store) PublishOutbox(ctx context.Context, publish func(context.Context, string) error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, "SELECT id,operation_id FROM outbox WHERE processed_at IS NULL ORDER BY id LIMIT 32 FOR UPDATE SKIP LOCKED")
	if err != nil {
		return err
	}
	type item struct {
		id        int64
		operation string
	}
	items := []item{}
	for rows.Next() {
		var item item
		if err = rows.Scan(&item.id, &item.operation); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range items {
		if err = publish(ctx, item.operation); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "UPDATE outbox SET processed_at=now() WHERE id=$1", item.id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
