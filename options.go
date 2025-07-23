package jwt

import "time"

type Option func(v *Validator)

func WithJSONUnmarshaler(fn func(data []byte, v any) error) Option {
	return func(v *Validator) {
		v.unmarshalJson = fn
	}
}

func WithIssuer(iss string) Option {
	return func(v *Validator) {
		v.issuer = iss
	}
}

func WithAudience(aud string) Option {
	return func(v *Validator) {
		v.audience = aud
	}
}

func WithClock(fn func() time.Time) Option {
	return func(v *Validator) {
		v.clock = fn
	}
}

func WithClockSkew(seconds int) Option {
	return func(v *Validator) {
		v.clockSkew = seconds
	}
}

func WithoutClaimValidation() Option {
	return func(v *Validator) {
		v.validClaims = false
	}
}
