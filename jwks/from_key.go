package jwks

import "crypto/ed25519"

func FromKey(pub ed25519.PublicKey) JWKS {
	return &pubKey{
		key: JWK{
			Alg: "EdDSA",
			X:   pub,
		},
	}
}

type pubKey struct {
	key JWK
}

// Get implements JWKS.
func (p *pubKey) Get(string) (jwk JWK, ok bool) {
	return p.key, true
}
