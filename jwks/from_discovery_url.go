package jwks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func FromDiscoveryURL(ctx context.Context, issuer string, interval time.Duration, handleErr ...func(error)) JWKS {
	u := &discoveryUrl{
		issuer: issuer,
	}

	// Lock until we have refreshed a first time.
	u.url.mu.Lock()

	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()

		for {
			if err := u.refresh(ctx, issuer); err != nil {
				if handleErr != nil && handleErr[0] != nil {
					handleErr[0](err)
				}
			}

			u.url.mu.Unlock()

			select {

			case <-ctx.Done():
				return

			case <-tick.C:
			}

			u.url.mu.Lock()
		}
	}()

	return u
}

type discoveryUrl struct {
	url    urlJwks
	issuer string
}

func (u *discoveryUrl) Get(kid string) (jwk JWK, ok bool) {
	return u.url.Get(kid)
}

func (u *discoveryUrl) Issuer() string {
	return u.issuer
}

func (u *discoveryUrl) refresh(ctx context.Context, issuer string) (err error) {
	url := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	if err != nil {
		return fmt.Errorf("failed to create HTTP request for Discovery: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		return fmt.Errorf("failed to perform HTTP request for Discovery: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("invalid response code from Discovery: %d", resp.StatusCode)
	}

	var disc discovery

	if err = json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return fmt.Errorf("failed to decode Discovery response: %w", err)
	}

	if disc.Issuer != issuer {
		return fmt.Errorf("mismatching issuer: discovered %s, expected %s", disc.Issuer, issuer)
	}

	return u.url.refresh(ctx, disc.JwksUri)
}

type discovery struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri"`
}
