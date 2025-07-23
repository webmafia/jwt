package jwks

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

type JWK struct {
	Alg string
	X   []byte
}

func (jwk JWK) Verify(msg, sig []byte) error {
	switch jwk.Alg {

	case "EdDSA":
		if !ed25519.Verify(jwk.X, msg, sig) {
			return errors.New("invalid signature")
		}

	default:
		return fmt.Errorf("unsupported algorithm: %s", jwk.Alg)
	}

	return nil
}
