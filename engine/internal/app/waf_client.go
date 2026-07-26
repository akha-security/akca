package app

import (
	"context"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type wafHTTPAdapter struct {
	client *httpclient.Client
}

func (a wafHTTPAdapter) Do(ctx context.Context, method, rawURL string, body []byte, headers map[string]string) (int, string, error) {
	rr, err := a.client.Do(ctx, method, rawURL, body, headers)
	if err != nil {
		return 0, "", err
	}
	return rr.Response.StatusCode, rr.Response.Body, nil
}
