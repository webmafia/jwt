package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

func FromURL(ctx context.Context, url string, interval time.Duration, handleErr ...func(error)) JWKS {
	u := &urlJwks{}

	// Lock until we have refreshed a first time.
	u.mu.Lock()

	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()

		for {
			if err := u.refresh(ctx, url); err != nil {
				if handleErr != nil && handleErr[0] != nil {
					handleErr[0](err)
				}
			}

			u.mu.Unlock()

			select {

			case <-ctx.Done():
				return

			case <-tick.C:
			}

			u.mu.Lock()
		}
	}()

	return u
}

type urlJwks struct {
	jwks jwks
	mu   sync.RWMutex
}

func (u *urlJwks) Get(kid string) (jwk JWK, ok bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.jwks.Get(kid)
}

func (u *urlJwks) refresh(ctx context.Context, url string) (err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	if err != nil {
		return fmt.Errorf("failed to create HTTP request for JWKS: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		return fmt.Errorf("failed to perform HTTP request for JWKS: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("invalid response code: %d", resp.StatusCode)
	}

	if err = json.NewDecoder(resp.Body).Decode(&u.jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS response: %w", err)
	}

	return
}
