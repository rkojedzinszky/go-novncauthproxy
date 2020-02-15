package token

import (
	"net/http"
	"strings"
)

func lastURIComponent(r *http.Request) string {
	components := strings.Split(r.URL.RequestURI(), "/")

	return components[len(components)-1]
}
