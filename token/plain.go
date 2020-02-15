package token

import (
	"fmt"
	"net/http"
	"strings"
)

type plainParser struct {
}

// NewPlainParser creates a plain URI parser
func NewPlainParser() Parser {
	return plainParser{}
}

func (p plainParser) ExtractControlRequest(r *http.Request) (*ControlRequest, error) {
	token := lastURIComponent(r)

	data := strings.Split(token, ",")
	if len(data) < 1 || data[0] == "" {
		return nil, fmt.Errorf("plainParser: error parsing")
	}

	control := &ControlRequest{
		Destination: data[0],
	}
	if len(data) >= 2 {
		control.Password = data[1]
	}

	return control, nil
}
