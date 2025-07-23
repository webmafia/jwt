package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/valyala/fastjson"
	"github.com/webmafia/fast"
	"github.com/webmafia/fast/buffer"
	"github.com/webmafia/jwt/jwks"
)

type Validator struct {
	jwks          jwks.JWKS
	bufPool       buffer.Pool
	parPool       fastjson.ParserPool
	unmarshalJson func(data []byte, v any) error
	issuer        string
	audience      string
	clock         func() time.Time
	clockSkew     int
	validClaims   bool
}

func NewValidator(jwks jwks.JWKS, opt ...Option) *Validator {
	v := &Validator{
		jwks:          jwks,
		unmarshalJson: json.Unmarshal,
		clock:         time.Now,
		clockSkew:     60,
		validClaims:   true,
	}

	if iss, ok := jwks.(issuer); ok {
		v.issuer = iss.Issuer()
	}

	for _, o := range opt {
		o(v)
	}

	return v
}

func (v *Validator) Validate(tok []byte, dst any) (err error) {
	sep1 := bytes.IndexByte(tok, '.')

	if sep1 < 0 {
		return errors.New("invalid jwt")
	}

	sep2 := bytes.IndexByte(tok[sep1+1:], '.')

	if sep2 < 0 {
		return errors.New("invalid jwt")
	}

	sep2 += sep1 + 1

	head := tok[:sep1]
	payload := tok[sep1+1 : sep2]
	signature := tok[sep2+1:]

	if len(head) == 0 || len(payload) == 0 || len(signature) == 0 {
		return errors.New("invalid jwt")
	}

	buf := v.bufPool.Get()
	defer v.bufPool.Put(buf)

	parser := v.parPool.Get()
	defer v.parPool.Put(parser)

	if err = decodeBase64(buf, head); err != nil {
		return
	}

	val, err := parser.ParseBytes(buf.B)

	if err != nil {
		return
	}

	kid := fast.BytesToString(val.GetStringBytes("kid"))
	jwk, ok := v.jwks.Get(kid)

	if !ok {
		return fmt.Errorf("invalid kid: %s", kid)
	}

	if err = decodeBase64(buf, signature); err != nil {
		return
	}

	if err = jwk.Verify(tok[:sep2], buf.B); err != nil {
		return
	}

	// If we came here, the token can be trusted.

	if v.validClaims || dst != nil {
		if err = decodeBase64(buf, payload); err != nil {
			return
		}
	}

	if v.validClaims {
		if val, err = parser.ParseBytes(buf.B); err != nil {
			return
		}

		if err = v.validateClaims(val); err != nil {
			return fmt.Errorf("failed claims validation: %w", err)
		}
	}

	if dst != nil {
		if err = v.unmarshalJson(buf.B, dst); err != nil {
			return
		}
	}

	return
}

func (v *Validator) validateClaims(claims *fastjson.Value) (err error) {
	if v.issuer != "" {
		iss := claims.GetStringBytes("iss")

		if fast.BytesToString(iss) != v.issuer {
			return errors.New("invalid token issuer")
		}
	}

	if v.audience != "" {
		aud := claims.Get("aud")

		switch typ := aud.Type(); typ {

		case fastjson.TypeString:
			str, err := aud.StringBytes()

			if err != nil {
				return fmt.Errorf("malformed token audience: %w", err)
			}

			if fast.BytesToString(str) != v.audience {
				return errors.New("invalid token audience")
			}

		case fastjson.TypeArray:
			strs, err := aud.Array()

			if err != nil {
				return fmt.Errorf("malformed token audience: %w", err)
			}

			var valid bool

			for _, val := range strs {
				str, _ := val.StringBytes()

				if fast.BytesToString(str) == v.audience {
					valid = true
					break
				}
			}

			if !valid {
				return errors.New("invalid token audience")
			}

		default:
			return fmt.Errorf("invalid type for token audience: %s", typ)

		}
	}

	now := int(v.clock().Unix())

	if iat := claims.GetInt("iat"); iat > 0 {
		if iat > now+v.clockSkew {
			return errors.New("token isn't issued yet")
		}
	}

	if nbf := claims.GetInt("nbf"); nbf > 0 {
		if left := nbf - (now - v.clockSkew); left > 0 {
			return fmt.Errorf("token is not valid until %d seconds", left)
		}
	}

	if exp := claims.GetInt("exp"); exp > 0 {
		if left := (exp + v.clockSkew) - now; left < 0 {
			return fmt.Errorf("token expired %d seconds ago", -left)
		}
	}

	return
}

func decodeBase64(dst *buffer.Buffer, src []byte) (err error) {
	l := base64.RawURLEncoding.DecodedLen(len(src))
	dst.Reset()
	dst.Grow(l)
	dst.B = dst.B[:l]

	_, err = base64.RawURLEncoding.Decode(dst.B, src)
	return
}
