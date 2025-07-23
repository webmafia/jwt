package jwt

import (
	"fmt"
	"testing"

	"github.com/webmafia/jwt/jwks"
)

func exampleJwks() jwks.JWKS {
	j, err := jwks.FromED25519(`
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAwmK6SSAu2E9V7uynkCKEaj5nZJyTvNG4x0KohsRzLpg=
-----END PUBLIC KEY-----
	`)

	if err != nil {
		panic(err)
	}

	return j
}

func exampleToken() []byte {
	return []byte("eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JkKWCY39IdWEQttmdqR7VdsvT-_QxheW_eb0S5wr_j83ltux_JDUIXs7a3Dtn3xuqzuhetiuJrWIvy5TzimeCg")
}

func Example() {
	v := NewValidator(exampleJwks())
	tok := exampleToken()

	var payload struct {
		Name string `json:"name"`
	}

	err := v.Validate(tok, &payload)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(payload.Name)

	// Output: John Doe
}

func Benchmark(b *testing.B) {
	v := NewValidator(exampleJwks())
	tok := exampleToken()

	for b.Loop() {
		_ = v.Validate(tok, nil)
	}
}
