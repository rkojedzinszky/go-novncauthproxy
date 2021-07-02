package token_test

import (
	"crypto/rand"
	"testing"
	"time"

	. "github.com/rkojedzinszky/go-novncauthproxy/token"
)

func TestEncodeDecode(t *testing.T) {
	cr := ControlRequest{Destination: "url"}

	key := make([]byte, 32)
	rand.Read(key)

	encoder, err := NewJWEEncoder(key)
	if err != nil {
		t.Fatal(err)
	}

	token := encoder.EncodeWithExpiry(&cr, time.Now().Add(1*time.Second))

	parser, err := NewJWEParser(key)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := parser.Decode(token)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if cr.Destination != decoded.Destination {
		t.Error("Encoded and decoded Destination does not match")
	}
}

func TestExpired(t *testing.T) {
	cr := ControlRequest{Destination: "url"}

	key := make([]byte, 32)
	rand.Read(key)

	encoder, err := NewJWEEncoder(key)
	if err != nil {
		t.Fatal(err)
	}

	token := encoder.EncodeWithExpiry(&cr, time.Now().Add(-1*time.Second))

	parser, err := NewJWEParser(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = parser.Decode(token)

	if err == nil {
		t.Error("Expected decode failure")
	}
}
