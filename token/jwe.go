package token

import (
	"fmt"
	"net/http"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

type jweParser struct {
	key []byte
}

// NewJWEParser returns a new JWE Parser instance
func NewJWEParser(key []byte) Parser {
	return jweParser{key: key}
}

type claims struct {
	// Public claims
	jwt.Claims

	Control ControlRequest `json:"vnc"`
}

func (j jweParser) ExtractControlRequest(r *http.Request) (*ControlRequest, error) {
	token := lastURIComponent(r)

	object, err := jwt.ParseEncrypted(token)
	if err != nil {
		return nil, fmt.Errorf("Jose parse: %+v", err)
	}

	claims := &claims{}
	if err := object.Claims(j.key, claims); err != nil {
		return nil, fmt.Errorf("Jose claims: %+v", err)
	}

	if err := claims.Validate(jwt.Expected{Time: time.Now()}); err != nil {
		return nil, fmt.Errorf("Jose validate: %+v", err)
	}

	return &claims.Control, nil
}
