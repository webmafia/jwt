package jwt

type issuer interface {
	Issuer() string
}
