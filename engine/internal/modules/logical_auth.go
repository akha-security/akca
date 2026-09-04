package modules

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/reflection"
)

// profiledHTTPDoer is required for every identity-bound proof. Falling back to
// the ambient scanner session would mix credentials and invalidate the result.
type profiledHTTPDoer interface {
	DoWithAuthProfile(ctx context.Context, method, rawURL string, body []byte, headers map[string]string,
		profile config.AuthProfile) (httpclient.RequestResponse, error)
}

func (r *Runner) probeAsProfileWithValue(ctx context.Context, profile config.AuthProfile,
	target ScanTarget, parameter, value string) (httpclient.RequestResponse, error) {
	client, ok := r.client.(profiledHTTPDoer)
	if !ok {
		return httpclient.RequestResponse{}, fmt.Errorf("isolated authentication profiles are unavailable")
	}
	method := strings.ToUpper(strings.TrimSpace(target.Method))
	if method == "" {
		method = http.MethodGet
	}
	location := target.Location
	if location == "" {
		location = target.Profile.ParameterLocation
	}
	probeURL, body, headers, err := reflection.BuildProbeRequest(
		target.EndpointURL, method, parameter, location, value,
	)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	headers = mergeHeaders(headers, r.wafHeaders(target.EndpointURL))
	return client.DoWithAuthProfile(ctx, effectiveMethod(method, location), probeURL, body, headers, profile)
}
