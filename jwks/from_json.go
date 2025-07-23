package jwks

import (
	"encoding/base64"
	"encoding/json"
	"slices"

	"github.com/webmafia/fast"
)

func FromJSON(jsonStr string) (_ JWKS, err error) {
	j := &jwks{}

	if err = j.UnmarshalJSON(fast.StringToBytes(jsonStr)); err != nil {
		return
	}

	return j, nil
}

type jwks struct {
	ids  []string
	keys []JWK
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *jwks) UnmarshalJSON(b []byte) (err error) {
	var jj jwksJson

	if err = json.Unmarshal(b, &jj); err != nil {
		return
	}

	clear(j.keys)
	j.ids = slices.Grow(j.ids[:0], len(jj.Keys))
	j.keys = slices.Grow(j.keys[:0], len(jj.Keys))

	for _, jwk := range jj.Keys {
		xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)

		if err != nil {
			return err
		}

		j.ids = append(j.ids, jwk.Kid)
		j.keys = append(j.keys, JWK{
			Alg: jwk.Alg,
			X:   xBytes,
		})
	}

	return
}

func (j *jwks) Get(kid string) (jwk JWK, ok bool) {
	idx := slices.Index(j.ids, kid)

	if idx < 0 {
		return
	}

	return j.keys[idx], true
}

type jwksJson struct {
	Keys []struct {
		Alg string `json:"alg"`
		Crv string `json:"crv"`
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		X   string `json:"x"`
	} `json:"keys"`
}
