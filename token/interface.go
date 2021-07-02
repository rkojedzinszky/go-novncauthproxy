package token

import (
	"net/http"
	"time"
)

// ControlRequest contains VNC server data
type ControlRequest struct {
	Destination string `json:"a"`
	Password    string `json:"p,omitempty"`
}

// Encoder encodes a ControlRequest into a token
type Encoder interface {
	EncodeWithExpiry(*ControlRequest, time.Time) string
}

// Decoder decodes a token into a ControlRequest
type Decoder interface {
	Decode(string) (*ControlRequest, error)
}

// Parser interface extracts ControlRequest token
// from a http.Request
type Parser interface {
	Decoder

	ExtractControlRequest(r *http.Request) (*ControlRequest, error)
}
