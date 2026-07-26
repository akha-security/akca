package apikeyvalidator

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/storage"
)

type Result struct {
	Service   string   `json:"service"`
	Status    string   `json:"status"`
	Scopes    []string `json:"scopes,omitempty"`
	Risk      string   `json:"risk"`
	TokenHint string   `json:"token_hint"`
	Validated bool     `json:"validated"`
}

type Validator struct {
	db      *storage.DB
	client  *http.Client
	limiter sync.Mutex
	lastReq time.Time
}

func New(db *storage.DB) *Validator {
	return &Validator{db: db, client: &http.Client{Timeout: 8 * time.Second}}
}

var services = []struct {
	Name    string
	Prefix  string
	URL     string
	ScopeFn func(*http.Response, string) []string
}{
	{Name: "github", Prefix: "ghp_", URL: "https://api.github.com/user"},
	{Name: "aws", Prefix: "AKIA", URL: "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"},
	{Name: "slack", Prefix: "xox", URL: "https://slack.com/api/auth.test"},
	{Name: "stripe", Prefix: "sk_", URL: "https://api.stripe.com/v1/balance"},
	{Name: "google", Prefix: "AIza", URL: "https://www.googleapis.com/oauth2/v1/tokeninfo"},
	{Name: "azure", Prefix: "azure_", URL: "https://management.azure.com/subscriptions?api-version=2020-01-01"},
	{Name: "digitalocean", Prefix: "dop_v1_", URL: "https://api.digitalocean.com/v2/account"},
	{Name: "sendgrid", Prefix: "SG.", URL: "https://api.sendgrid.com/v3/scopes"},
	{Name: "twilio", Prefix: "SK", URL: "https://api.twilio.com/2010-04-01/Accounts.json"},
	{Name: "mailgun", Prefix: "key-", URL: "https://api.mailgun.net/v4/domains"},
}

func (v *Validator) DetectService(token string) string {
	for _, s := range services {
		if strings.HasPrefix(token, s.Prefix) {
			return s.Name
		}
	}
	return "unknown"
}

func (v *Validator) Validate(ctx context.Context, scanID, token string) (Result, error) {
	v.rateLimit()
	svc := v.DetectService(token)
	res := Result{Service: svc, TokenHint: hint(token), Risk: "medium"}
	if svc == "unknown" {
		res.Status = "unknown"
		_ = v.db.SaveAPIKeyValidation(scanID, svc, res.Status, res)
		return res, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, serviceURL(svc), nil)
	req.Header.Set("Authorization", authHeader(svc, token))
	resp, err := v.client.Do(req)
	if err != nil {
		res.Status = "rate-limited"
		_ = v.db.SaveAPIKeyValidation(scanID, svc, res.Status, res)
		return res, err
	}
	defer resp.Body.Close()
	res.Validated = true
	switch resp.StatusCode {
	case 200, 201:
		res.Status = "valid"
		res.Risk = "high"
		res.Scopes = []string{"read"}
	case 401, 403:
		res.Status = "invalid"
		res.Risk = "low"
	case 429:
		res.Status = "rate-limited"
	default:
		res.Status = "unknown"
	}
	_ = v.db.SaveAPIKeyValidation(scanID, svc, res.Status, res)
	return res, nil
}

func (v *Validator) rateLimit() {
	v.limiter.Lock()
	defer v.limiter.Unlock()
	if time.Since(v.lastReq) < 500*time.Millisecond {
		time.Sleep(500*time.Millisecond - time.Since(v.lastReq))
	}
	v.lastReq = time.Now()
}

func serviceURL(name string) string {
	for _, s := range services {
		if s.Name == name {
			return s.URL
		}
	}
	return ""
}

func authHeader(svc, token string) string {
	switch svc {
	case "stripe":
		return "Bearer " + token
	case "github":
		return "token " + token
	default:
		return "Bearer " + token
	}
}

func hint(token string) string {
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "..." + token[len(token)-4:]
}
