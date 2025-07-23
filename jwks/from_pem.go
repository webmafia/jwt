package jwks

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/webmafia/fast"
)

func FromED25519(pemData string) (_ JWKS, err error) {
	block, _ := pem.Decode(fast.StringToBytes(pemData))

	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	key, ok := pub.(ed25519.PublicKey)

	if !ok {
		return nil, errors.New("not an Ed25519 public key")
	}

	return FromKey(key), nil
}
