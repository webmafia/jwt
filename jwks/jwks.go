package jwks

type JWKS interface {
	Get(kid string) (jwk JWK, ok bool)
}
