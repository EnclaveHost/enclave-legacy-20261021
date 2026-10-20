//go:build !(shielddirect && bootstrapdirect && !releaselab)

package main

import (
	"context"
	"errors"
	"io"
)

// shieldDirectOwner exists only in the Shield-direct build (shield_direct.go). In every other build - SNP direct, legacy,
// lab - a Hyper-V domain without HOST_DATA behaves exactly as before: no owner-committed authority, self-signed or
// launcher-named certificate only.
func (f *front) shieldDirectOwner(_ context.Context, pipe io.WriteCloser, _ *shieldEgress) error {
	if directBootstrap && pipe != nil {
		pipe.Close()
		return errors.New("this direct build does not support Shield secret startup")
	}
	return nil
}
