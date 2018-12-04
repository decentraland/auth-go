package http

import (
	"github.com/decentraland/auth-go/auth"
	"github.com/decentraland/auth-go/utils"
	"net/http"
	"strings"
)

func TransformHttpRequest(r *http.Request) (*auth.AuthRequest, error) {
	credentials := make(map[string]string)
	for key, value := range r.Header {
		credentials[strings.ToLower(key)] = value[0]
	}

	content, err := utils.ReadRequestBody(r)
	if err != nil {
		return nil, err
	}

	return &auth.AuthRequest{
		Credentials: credentials,
		Content:     content,
		Method:      r.Method,
		URL:         r.URL.String(),
	}, nil
}
