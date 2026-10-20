package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type snapshotUnavailable struct{ error }

func (e *snapshotUnavailable) Unwrap() error { return e.error }

// AuthorizeWhenConfirmed allows a newly claimed lease to enter the confirmed
// chain view. A transaction receipt does not imply that head-confirmations
// already contains that transaction. Every attempt applies the full existing
// quorum, freshness, rollback, identity and owner-commitment checks. No config
// or custody authorization is returned until those checks succeed.
//
// Only chain snapshot failures retry. Invalid packages and a fresh agreeing
// owner/commitment mismatch fail immediately. Revalidate remains fail-closed
// without retries after custody retrieval.
func (r *Reader) AuthorizeWhenConfirmed(ctx context.Context, id [32]byte, raw []byte, loaded Identity) (*Authorization, error) {
	return r.authorizeWhenConfirmed(ctx, id, raw, loaded, 30*time.Second, 2*time.Second)
}

func (r *Reader) authorizeWhenConfirmed(ctx context.Context, id [32]byte, raw []byte, loaded Identity, window, interval time.Duration) (*Authorization, error) {
	ctx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("confirmed startup wait ended: %w", err)
		}
		auth, err := r.Authorize(ctx, id, raw, loaded)
		if err == nil {
			if e := ctx.Err(); e != nil {
				return nil, fmt.Errorf("confirmed startup wait ended: %w", e)
			}
			return auth, nil
		}
		var pending *snapshotUnavailable
		if !errors.As(err, &pending) {
			return nil, err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("confirmed startup wait ended (%v): %w", err, ctx.Err())
		case <-timer.C:
		}
	}
}
