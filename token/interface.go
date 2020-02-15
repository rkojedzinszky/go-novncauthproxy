package token

import "net/http"

// ControlRequest contains VNC server data
type ControlRequest struct {
	Destination string `json:"a"`
	Password    string `json:"p"`
}

// Parser interface extracts ControlRequest token
// from a http.Request
type Parser interface {
	ExtractControlRequest(r *http.Request) (*ControlRequest, error)
}
