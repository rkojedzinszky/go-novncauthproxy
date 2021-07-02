package token

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	invalidKeyError = errors.New("invalid key length, must be 32 bytes")
)

type jwe struct {
	key []byte
}

// NewJWEParser returns a new JWE Parser instance
func NewJWEParser(key []byte) (Parser, error) {
	if len(key) != 32 {
		return nil, invalidKeyError
	}

	return jwe{key: key}, nil
}

type claims struct {
	// Public claims
	jwt.Claims

	Control ControlRequest `json:"vnc"`
}

func (j jwe) Decode(token string) (*ControlRequest, error) {
	object, err := jwt.ParseEncrypted(token)
	if err != nil {
		return nil, fmt.Errorf("Jose parse: %+v", err)
	}

	claims := &claims{}
	if err := object.Claims(j.key, claims); err != nil {
		return nil, fmt.Errorf("Jose claims: %+v", err)
	}

	if err := claims.ValidateWithLeeway(jwt.Expected{Time: time.Now()}, 0); err != nil {
		return nil, fmt.Errorf("Jose validate: %+v", err)
	}

	return &claims.Control, nil
}

func (j jwe) ExtractControlRequest(r *http.Request) (*ControlRequest, error) {
	return j.Decode(lastURIComponent(r))
}

type jweencoder struct {
	builder jwt.Builder
}

func NewJWEEncoder(key []byte) (Encoder, error) {
	if len(key) != 32 {
		return nil, invalidKeyError
	}

	encrypter, err := jose.NewEncrypter(
		jose.A256CBC_HS512,
		jose.Recipient{
			Algorithm: jose.A256KW,
			Key:       key,
		},
		nil,
	)

	if err != nil {
		return nil, err
	}

	return jweencoder{
		builder: jwt.Encrypted(encrypter),
	}, nil
}

func (j jweencoder) EncodeWithExpiry(control *ControlRequest, exp time.Time) string {
	token, _ := j.builder.Claims(claims{
		Claims: jwt.Claims{
			Expiry: jwt.NewNumericDate(exp),
		},
		Control: *control,
	}).CompactSerialize()

	return token
}
