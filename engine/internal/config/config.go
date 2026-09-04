package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultOASTServers is an ordered startup fallback chain. Registration is
// attempted from left to right and stops at the first successful server.
const DefaultOASTServers = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me,interact.sh"

type UserAgentMode string

const (
	UserAgentRandom UserAgentMode = "random"
	UserAgentReal   UserAgentMode = "real"
	UserAgentCustom UserAgentMode = "custom"
)

type PayloadBudget string

const (
	PayloadBudgetLow       PayloadBudget = "low"
	PayloadBudgetMedium    PayloadBudget = "medium"
	PayloadBudgetHigh      PayloadBudget = "high"
	PayloadBudgetUnlimited PayloadBudget = "unlimited"
)

type CredentialStorageMode string

const (
	CredentialStorageMemory        CredentialStorageMode = "memory"
	CredentialStorageEncryptedDisk CredentialStorageMode = "encrypted_disk"
	CredentialStorageOSKeychain    CredentialStorageMode = "os_keychain"
)

type AuthProfile struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Headers map[string]string `json:"headers,omitempty"`
	Cookies map[string]string `json:"cookies,omitempty"`
}

type RoleProfile struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	AuthProfileID string `json:"auth_profile_id"`
}

type RateLimitPolicy struct {
	URLContains     string `json:"url_contains"`
	Account         string `json:"account"`
	Threshold       int    `json:"threshold"`
	CooldownSeconds int    `json:"cooldown_seconds"`
	PerIP           bool   `json:"per_ip"`
	PerAccount      bool   `json:"per_account"`
}

// AuthorizationPolicy describes an application-specific authorization
// contract. The scanner never invents roles, privileged actions, or cleanup
// requests: BFLA proof is attempted only when this contract is supplied.
type AuthorizationPolicy struct {
	ID                   string `json:"id"`
	URLContains          string `json:"url_contains"`
	Method               string `json:"method"`
	LowRoleProfileID     string `json:"low_role_profile_id"`
	HighRoleProfileID    string `json:"high_role_profile_id"`
	ExpectedRolePolicy   string `json:"expected_role_policy"`
	ActionBody           string `json:"action_body,omitempty"`
	ActionContentType    string `json:"action_content_type,omitempty"`
	StateURL             string `json:"state_url"`
	StateMethod          string `json:"state_method,omitempty"`
	CleanupURL           string `json:"cleanup_url"`
	CleanupMethod        string `json:"cleanup_method"`
	CleanupBody          string `json:"cleanup_body,omitempty"`
	CleanupContentType   string `json:"cleanup_content_type,omitempty"`
	RequireAnonymousDeny bool   `json:"require_anonymous_deny"`
}

// ObjectAuthorizationPolicy is an explicit ownership contract for BOLA/IDOR
// verification. A shared 200 response is not a vulnerability unless the
// resource is declared as owned by one role and forbidden to the other.
type ObjectAuthorizationPolicy struct {
	ID                   string   `json:"id"`
	URLContains          string   `json:"url_contains"`
	Method               string   `json:"method"`
	Parameter            string   `json:"parameter"`
	Location             string   `json:"location,omitempty"`
	OwnerRoleProfileID   string   `json:"owner_role_profile_id"`
	ForeignRoleProfileID string   `json:"foreign_role_profile_id"`
	ResourceValues       []string `json:"resource_values"`
	ExpectedPolicy       string   `json:"expected_policy"`
	RequireAnonymousDeny bool     `json:"require_anonymous_deny"`
}

type SelfHostedOASTConfig struct {
	Domain      string `json:"domain"`
	HTTPAddr    string `json:"http_addr,omitempty"`
	HTTPSAddr   string `json:"https_addr,omitempty"`
	TLSCertFile string `json:"tls_cert_file,omitempty"`
	TLSKeyFile  string `json:"tls_key_file,omitempty"`
	DNSAddr     string `json:"dns_addr,omitempty"`
	SMTPAddr    string `json:"smtp_addr,omitempty"`
	LDAPAddr    string `json:"ldap_addr,omitempty"`
}

type RecordedRequest struct {
	Method           string            `json:"method"`
	URL              string            `json:"url"`
	Body             string            `json:"body,omitempty"`
	ContentType      string            `json:"content_type,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	ExpectedStatuses []int             `json:"expected_statuses,omitempty"`
}

// RaceProofPolicy is deliberately application-specific. Transaction IDs and
// cleanup requests cannot be guessed safely by a generic scanner.
type RaceProofPolicy struct {
	ID                      string          `json:"id"`
	URLContains             string          `json:"url_contains"`
	AuthProfileID           string          `json:"auth_profile_id"`
	Action                  RecordedRequest `json:"action"`
	State                   RecordedRequest `json:"state"`
	Cleanup                 RecordedRequest `json:"cleanup"`
	TransactionIDExpression string          `json:"transaction_id_expression"`
	SequentialRuns          int             `json:"sequential_runs,omitempty"`
	ConcurrentRuns          int             `json:"concurrent_runs,omitempty"`
}

type BusinessLogicProofPolicy struct {
	ID                      string          `json:"id"`
	URLContains             string          `json:"url_contains"`
	AuthProfileID           string          `json:"auth_profile_id"`
	ExpectedInvariant       string          `json:"expected_invariant"`
	NativeAction            RecordedRequest `json:"native_action"`
	ManipulatedAction       RecordedRequest `json:"manipulated_action"`
	NegativeControl         RecordedRequest `json:"negative_control"`
	State                   RecordedRequest `json:"state"`
	Cleanup                 RecordedRequest `json:"cleanup"`
	TransactionIDExpression string          `json:"transaction_id_expression"`
	StateValueExpression    string          `json:"state_value_expression"`
	ForbiddenValue          string          `json:"forbidden_value"`
}

// StatefulSecurityProofPolicy defines an application-specific, reversible
// security check. Generic scanners cannot infer whether a password reset or
// webhook was actually applied from an HTTP 2xx response, so these modules run
// only when an independent state read and a cleanup request are supplied.
type StatefulSecurityProofPolicy struct {
	ID                string          `json:"id"`
	URLContains       string          `json:"url_contains"`
	AuthProfileID     string          `json:"auth_profile_id,omitempty"`
	ExpectedInvariant string          `json:"expected_invariant"`
	Action            RecordedRequest `json:"action"`
	NegativeControl   RecordedRequest `json:"negative_control"`
	State             RecordedRequest `json:"state"`
	Cleanup           RecordedRequest `json:"cleanup"`
}

// SessionLifecycleProofPolicy uses a credential explicitly marked disposable.
// A successful logout intentionally revokes it, so the scanner must never use
// the ambient crawl session for this proof.
type SessionLifecycleProofPolicy struct {
	ID                   string          `json:"id"`
	URLContains          string          `json:"url_contains"`
	AuthProfileID        string          `json:"auth_profile_id"`
	ExpectedInvariant    string          `json:"expected_invariant"`
	DisposableCredential bool            `json:"disposable_credential"`
	Logout               RecordedRequest `json:"logout"`
	ProtectedResource    RecordedRequest `json:"protected_resource"`
}

type FileUploadProofPolicy struct {
	ID            string `json:"id"`
	URLContains   string `json:"url_contains"`
	CleanupMethod string `json:"cleanup_method"`
	CleanupURL    string `json:"cleanup_url"`
}

type CacheDeceptionProofPolicy struct {
	ID            string `json:"id"`
	URLContains   string `json:"url_contains"`
	PrivateCanary string `json:"private_canary"`
}

type HPPProofPolicy struct {
	ID                   string          `json:"id"`
	URLContains          string          `json:"url_contains"`
	AuthProfileID        string          `json:"auth_profile_id"`
	ExpectedInvariant    string          `json:"expected_invariant"`
	NativeValue          string          `json:"native_value"`
	DuplicateValues      []string        `json:"duplicate_values"`
	State                RecordedRequest `json:"state"`
	Cleanup              RecordedRequest `json:"cleanup"`
	StateValueExpression string          `json:"state_value_expression"`
	ForbiddenValue       string          `json:"forbidden_value"`
}

type ScanConfig struct {
	ScanID                        string                        `json:"scan_id"`
	AppName                       string                        `json:"app_name"`
	Targets                       []string                      `json:"targets"`
	APIImportFiles                []string                      `json:"api_import_files,omitempty"`
	IncludeDomains                []string                      `json:"include_domains"`
	ExcludeDomains                []string                      `json:"exclude_domains"`
	ExcludedPaths                 []string                      `json:"excluded_paths"`
	Authentication                map[string]string             `json:"authentication,omitempty"`
	SessionCookies                map[string]string             `json:"session_cookies,omitempty"`
	CustomHeaders                 map[string]string             `json:"custom_headers,omitempty"`
	ApiKeys                       map[string]string             `json:"api_keys,omitempty"`
	KnownAccounts                 []string                      `json:"known_accounts,omitempty"`
	JWTExpiredTokens              []string                      `json:"jwt_expired_tokens,omitempty"`
	RateLimitPolicies             []RateLimitPolicy             `json:"rate_limit_policies,omitempty"`
	AuthorizationPolicies         []AuthorizationPolicy         `json:"authorization_policies,omitempty"`
	ObjectAuthorizationPolicies   []ObjectAuthorizationPolicy   `json:"object_authorization_policies,omitempty"`
	RaceProofPolicies             []RaceProofPolicy             `json:"race_proof_policies,omitempty"`
	BusinessLogicProofPolicies    []BusinessLogicProofPolicy    `json:"business_logic_proof_policies,omitempty"`
	AccountRecoveryProofPolicies  []StatefulSecurityProofPolicy `json:"account_recovery_proof_policies,omitempty"`
	WebhookProofPolicies          []StatefulSecurityProofPolicy `json:"webhook_proof_policies,omitempty"`
	CSRFProofPolicies             []StatefulSecurityProofPolicy `json:"csrf_proof_policies,omitempty"`
	SessionLifecycleProofPolicies []SessionLifecycleProofPolicy `json:"session_lifecycle_proof_policies,omitempty"`
	FileUploadProofPolicies       []FileUploadProofPolicy       `json:"file_upload_proof_policies,omitempty"`
	CacheDeceptionProofPolicies   []CacheDeceptionProofPolicy   `json:"cache_deception_proof_policies,omitempty"`
	HPPProofPolicies              []HPPProofPolicy              `json:"hpp_proof_policies,omitempty"`
	ProxyURL                      string                        `json:"proxy_url,omitempty"`
	ScanIntensity                 string                        `json:"scan_intensity"`
	TimeBudget                    time.Duration                 `json:"time_budget"`
	RequestBudget                 int                           `json:"request_budget"`
	CrawlerRequestBudget          int                           `json:"crawler_request_budget,omitempty"`
	PayloadBudget                 PayloadBudget                 `json:"payload_budget"`
	AllowedVulnerabilityClasses   []string                      `json:"allowed_vulnerability_classes,omitempty"`
	UserAgentMode                 UserAgentMode                 `json:"user_agent_mode"`
	UserAgents                    []string                      `json:"user_agents,omitempty"`
	GlobalRateLimit               float64                       `json:"global_rate_limit"`
	PerHostRateLimit              float64                       `json:"per_host_rate_limit"`
	MaxConcurrency                int                           `json:"max_concurrency"`
	PerHostConcurrency            int                           `json:"per_host_concurrency"`
	MaxDepth                      int                           `json:"max_depth"`
	MaxPages                      int                           `json:"max_pages"`
	SubdomainCount                int                           `json:"subdomain_count,omitempty"`
	MaxEndpoints                  int                           `json:"max_endpoints,omitempty"`
	IncludeLinkedAPISubdomains    bool                          `json:"include_linked_api_subdomains,omitempty"`
	MaxMemoryMB                   int                           `json:"max_memory_mb,omitempty"`
	MemoryLimitSource             string                        `json:"memory_limit_source,omitempty"`
	DetectedAvailableMemoryMB     int                           `json:"detected_available_memory_mb,omitempty"`
	FollowRedirects               bool                          `json:"follow_redirects"`
	EnableHeadlessCrawler         bool                          `json:"enable_headless_crawler"`
	EnableJSAnalysis              bool                          `json:"enable_js_analysis"`
	EnableWAFDetection            bool                          `json:"enable_waf_detection"`
	EnableOAST                    bool                          `json:"enable_oast"`
	OASTServerURL                 string                        `json:"oast_server_url,omitempty"`
	OASTSelfHosted                *SelfHostedOASTConfig         `json:"oast_self_hosted,omitempty"`
	OASTPollInterval              time.Duration                 `json:"oast_poll_interval"`
	OASTDrainTimeout              time.Duration                 `json:"oast_drain_timeout,omitempty"`
	EnableFuzzing                 bool                          `json:"enable_fuzzing"`
	Enable403BypassChecks         bool                          `json:"enable_403_bypass_checks"`
	EnableRawTrafficStorage       bool                          `json:"enable_raw_traffic_storage"`
	RedactionEnabled              bool                          `json:"redaction_enabled"`
	SmartScanProfile              string                        `json:"smart_scan_profile"`
	// PassiveMode is an execution safety invariant, not merely a UI label. When
	// set, active calibration, mutation, browser execution and fuzzing phases
	// are disabled again at scan bootstrap even if a caller supplied conflicting
	// defaults later.
	PassiveMode                  bool                  `json:"passive_mode,omitempty"`
	AuthProfiles                 []AuthProfile         `json:"auth_profiles,omitempty"`
	RoleProfiles                 []RoleProfile         `json:"role_profiles,omitempty"`
	CredentialStorageMode        CredentialStorageMode `json:"credential_storage_mode"`
	EnableEncryptedSecretStorage bool                  `json:"enable_encrypted_secret_storage"`
	EnableScanResume             bool                  `json:"enable_scan_resume"`
	EnableFindingCorrelation     bool                  `json:"enable_finding_correlation"`
	EnableBrowserWorkerPool      bool                  `json:"enable_browser_worker_pool"`
	BrowserWorkerPoolSize        int                   `json:"browser_worker_pool_size"`
	EnableHealthMonitoring       bool                  `json:"enable_health_monitoring"`
	EnableRulePackUpdates        bool                  `json:"enable_rule_pack_updates"`
	RulePackChannels             []string              `json:"rule_pack_channels,omitempty"`
	ReportTemplate               string                `json:"report_template"`
	OutputDirectory              string                `json:"output_directory,omitempty"`
	ReportFormats                []string              `json:"report_formats,omitempty"`
	EnableProxyInterceptMode     bool                  `json:"enable_proxy_intercept_mode"`
	EnableScanScheduler          bool                  `json:"enable_scan_scheduler"`
	ScanSchedule                 string                `json:"scan_schedule,omitempty"`
	EnableComparisonScan         bool                  `json:"enable_comparison_scan"`
	DNSResolvers                 []string              `json:"dns_resolvers,omitempty"`
	EnableRaceConditionTesting   bool                  `json:"enable_race_condition_testing"`
	EnableBusinessLogicChecks    bool                  `json:"enable_business_logic_checks"`
	EnableSecondOrderTracking    bool                  `json:"enable_second_order_tracking"`
	EnableWAFBypassHeaders       bool                  `json:"enable_waf_bypass_headers"`
	EnableRuntimeSensor          bool                  `json:"enable_runtime_sensor"`
	EnableInformationalChecks    bool                  `json:"enable_informational_checks"`
	RuntimeSensorListenAddr      string                `json:"runtime_sensor_listen_addr,omitempty"`
	RuntimeSensorTokenEnv        string                `json:"runtime_sensor_token_env,omitempty"`
	// ForceHTTP1 disables HTTP/2 ALPN negotiation (Burp-style). Required for some login flows.
	ForceHTTP1 bool `json:"force_http1"`
	// InsecureSkipVerify disables TLS certificate verification (USE WITH CAUTION - TESTING ONLY).
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
	// LoginCredentials triggers automated form login before crawling when populated.
	LoginCredentials *LoginCredentials `json:"login_credentials,omitempty"`
	// TestRoundTripper is used by integration tests to route lab hostnames to local httptest servers.
	TestRoundTripper http.RoundTripper `json:"-"`
	// SkipAutoReport lets CLI callers avoid the pipeline's internal JSON report
	// when they will immediately export the requested final format themselves.
	SkipAutoReport bool `json:"-"`
	// Explicit tracks CLI/UI choices that must not be overwritten by profiles.
	Explicit ExplicitScanOptions `json:"-"`
}

type ExplicitScanOptions struct {
	EnableOAST                 bool
	EnableFuzzing              bool
	EnableJSAnalysis           bool
	EnableWAFDetection         bool
	Enable403BypassChecks      bool
	EnableBusinessLogicChecks  bool
	EnableRaceConditionTesting bool
	EnableSecondOrderTracking  bool
	GlobalRateLimit            bool
	PerHostRateLimit           bool
	MaxConcurrency             bool
	PerHostConcurrency         bool
	EnableWAFBypassHeaders     bool
	RequestBudget              bool
	CrawlerRequestBudget       bool
	TimeBudget                 bool
	MaxPages                   bool
	MaxEndpoints               bool
	MaxDepth                   bool
}

type LoginCredentials struct {
	LoginURL           string `json:"login_url"`
	Username           string `json:"username,omitempty"`
	Email              string `json:"email,omitempty"`
	Password           string `json:"password,omitempty"`
	UsernameField      string `json:"username_field,omitempty"`
	PasswordField      string `json:"password_field,omitempty"`
	HeartbeatURL       string `json:"heartbeat_url,omitempty"`
	LoggedInMarker     string `json:"logged_in_marker,omitempty"`
	LoggedOutMarker    string `json:"logged_out_marker,omitempty"`
	DisableAutoRelogin bool   `json:"disable_auto_relogin,omitempty"`
}

func DefaultScanConfig() ScanConfig {
	return ScanConfig{
		ScanIntensity:                "fast",
		GlobalRateLimit:              20,
		PerHostRateLimit:             10,
		MaxConcurrency:               16,
		PerHostConcurrency:           8,
		MaxDepth:                     0,
		MaxPages:                     FullScanMaxPages,
		MaxEndpoints:                 FullScanMaxEndpoints,
		MaxMemoryMB:                  0,
		RequestBudget:                FullScanRequestBudget,
		CrawlerRequestBudget:         FullScanCrawlerRequestBudget,
		TimeBudget:                   0,
		PayloadBudget:                PayloadBudgetUnlimited,
		RedactionEnabled:             false,
		EnableWAFDetection:           true,
		EnableJSAnalysis:             true,
		EnableHeadlessCrawler:        true,
		EnableFuzzing:                true,
		Enable403BypassChecks:        true,
		EnableWAFBypassHeaders:       false,
		EnableOAST:                   true,
		OASTServerURL:                DefaultOASTServers,
		OASTPollInterval:             2 * time.Second,
		OASTDrainTimeout:             60 * time.Second,
		EnableEncryptedSecretStorage: true,
		EnableScanResume:             true,
		EnableFindingCorrelation:     true,
		EnableBrowserWorkerPool:      true,
		BrowserWorkerPoolSize:        3,
		EnableHealthMonitoring:       true,
		SmartScanProfile:             "Full Scan",
		ReportTemplate:               "HackerOne",
		UserAgentMode:                UserAgentReal,
		CredentialStorageMode:        CredentialStorageEncryptedDisk,
		FollowRedirects:              true,
		ForceHTTP1:                   true,
		EnableBusinessLogicChecks:    true,
		EnableRaceConditionTesting:   true,
		EnableSecondOrderTracking:    true,
		EnableRuntimeSensor:          true,
		EnableInformationalChecks:    true,
		RuntimeSensorListenAddr:      "127.0.0.1:19091",
		RuntimeSensorTokenEnv:        "AKCA_SENSOR_TOKEN",
	}
}

func (c *ScanConfig) Validate() error {
	proxyURL, err := NormalizeProxyURL(c.ProxyURL)
	if err != nil {
		return err
	}
	c.ProxyURL = proxyURL
	if c.MaxMemoryMB < 0 {
		return fmt.Errorf("max_memory_mb cannot be negative")
	}
	if c.EnableRuntimeSensor {
		if strings.TrimSpace(c.RuntimeSensorListenAddr) == "" {
			c.RuntimeSensorListenAddr = "127.0.0.1:19091"
		}
		host, _, splitErr := net.SplitHostPort(c.RuntimeSensorListenAddr)
		ip := net.ParseIP(host)
		if splitErr != nil || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return fmt.Errorf("runtime sensor collector must listen on an explicit loopback host:port")
		}
		if strings.TrimSpace(c.RuntimeSensorTokenEnv) == "" {
			c.RuntimeSensorTokenEnv = "AKCA_SENSOR_TOKEN"
		}
		if token, exists := os.LookupEnv(c.RuntimeSensorTokenEnv); exists && strings.TrimSpace(token) != "" &&
			len(strings.TrimSpace(token)) < 16 {
			return fmt.Errorf("runtime sensor token environment variable %q must contain at least 16 characters", c.RuntimeSensorTokenEnv)
		}
	}
	for index, policy := range c.RateLimitPolicies {
		if policy.URLContains == "" || policy.Account == "" || policy.Threshold < 1 || policy.Threshold > 50 ||
			policy.CooldownSeconds < 1 || policy.CooldownSeconds > 300 || (!policy.PerIP && !policy.PerAccount) {
			return fmt.Errorf("rate_limit_policies[%d] requires URL/account, threshold 1..50, cooldown 1..300 and an IP/account dimension", index)
		}
	}
	authProfileIDs := make(map[string]struct{}, len(c.AuthProfiles))
	for index, profile := range c.AuthProfiles {
		id := strings.TrimSpace(profile.ID)
		if id == "" {
			return fmt.Errorf("auth_profiles[%d].id is required", index)
		}
		if _, duplicate := authProfileIDs[id]; duplicate {
			return fmt.Errorf("duplicate auth profile id: %q", id)
		}
		authProfileIDs[id] = struct{}{}
	}
	roleProfileIDs := make(map[string]struct{}, len(c.RoleProfiles))
	for index, role := range c.RoleProfiles {
		id := strings.TrimSpace(role.ID)
		if id == "" || strings.TrimSpace(role.AuthProfileID) == "" {
			return fmt.Errorf("role_profiles[%d] requires id and auth_profile_id", index)
		}
		if _, duplicate := roleProfileIDs[id]; duplicate {
			return fmt.Errorf("duplicate role profile id: %q", id)
		}
		if _, exists := authProfileIDs[role.AuthProfileID]; !exists {
			return fmt.Errorf("role profile %q references unknown auth profile %q", id, role.AuthProfileID)
		}
		roleProfileIDs[id] = struct{}{}
	}

	switch c.UserAgentMode {
	case UserAgentRandom, UserAgentReal, UserAgentCustom, "":
		if c.UserAgentMode == "" {
			c.UserAgentMode = UserAgentReal
		}
	default:
		return fmt.Errorf("invalid user_agent_mode: %q", c.UserAgentMode)
	}
	if c.UserAgentMode == UserAgentCustom && len(c.UserAgents) == 0 {
		return fmt.Errorf("user_agents required when user_agent_mode is custom")
	}

	switch c.PayloadBudget {
	case PayloadBudgetLow, PayloadBudgetMedium, PayloadBudgetHigh, PayloadBudgetUnlimited, "":
		if c.PayloadBudget == "" {
			c.PayloadBudget = PayloadBudgetUnlimited
		}
	default:
		return fmt.Errorf("invalid payload_budget: %q", c.PayloadBudget)
	}

	switch c.CredentialStorageMode {
	case CredentialStorageMemory, CredentialStorageEncryptedDisk, CredentialStorageOSKeychain, "":
		if c.CredentialStorageMode == "" {
			c.CredentialStorageMode = CredentialStorageOSKeychain
		}
	default:
		return fmt.Errorf("invalid credential_storage_mode: %q", c.CredentialStorageMode)
	}

	if c.RequestBudget < 0 {
		return fmt.Errorf("request_budget cannot be negative: %d", c.RequestBudget)
	}
	if c.CrawlerRequestBudget < 0 {
		return fmt.Errorf("crawler_request_budget cannot be negative: %d", c.CrawlerRequestBudget)
	}
	if c.MaxPages < 0 {
		return fmt.Errorf("max_pages cannot be negative: %d", c.MaxPages)
	}
	if c.MaxEndpoints < 0 {
		return fmt.Errorf("max_endpoints cannot be negative: %d", c.MaxEndpoints)
	}
	if c.MaxDepth < 0 {
		return fmt.Errorf("max_depth cannot be negative: %d", c.MaxDepth)
	}
	if c.MaxConcurrency < 0 {
		return fmt.Errorf("max_concurrency cannot be negative: %d", c.MaxConcurrency)
	}
	if c.PerHostConcurrency < 0 {
		return fmt.Errorf("per_host_concurrency cannot be negative: %d", c.PerHostConcurrency)
	}
	if c.BrowserWorkerPoolSize < 0 {
		return fmt.Errorf("browser_worker_pool_size cannot be negative: %d", c.BrowserWorkerPoolSize)
	}
	if c.TimeBudget < 0 {
		return fmt.Errorf("time_budget cannot be negative: %v", c.TimeBudget)
	}

	if c.GlobalRateLimit <= 0 {
		c.GlobalRateLimit = 3
	}
	if c.PerHostRateLimit <= 0 {
		c.PerHostRateLimit = 2
	}
	seenPolicies := make(map[string]struct{}, len(c.AuthorizationPolicies))
	for index, policy := range c.AuthorizationPolicies {
		if strings.TrimSpace(policy.ID) == "" || strings.TrimSpace(policy.URLContains) == "" ||
			strings.TrimSpace(policy.Method) == "" || strings.TrimSpace(policy.LowRoleProfileID) == "" ||
			strings.TrimSpace(policy.HighRoleProfileID) == "" || strings.TrimSpace(policy.ExpectedRolePolicy) == "" ||
			strings.TrimSpace(policy.StateURL) == "" || strings.TrimSpace(policy.CleanupURL) == "" ||
			strings.TrimSpace(policy.CleanupMethod) == "" {
			return fmt.Errorf("authorization_policies[%d] is incomplete", index)
		}
		if _, duplicate := seenPolicies[policy.ID]; duplicate {
			return fmt.Errorf("duplicate authorization policy id: %q", policy.ID)
		}
		seenPolicies[policy.ID] = struct{}{}
		if policy.LowRoleProfileID == policy.HighRoleProfileID {
			return fmt.Errorf("authorization policy %q must use distinct low/high roles", policy.ID)
		}
		if _, exists := authProfileIDs[policy.LowRoleProfileID]; !exists {
			return fmt.Errorf("authorization policy %q references unknown low auth profile %q", policy.ID, policy.LowRoleProfileID)
		}
		if _, exists := authProfileIDs[policy.HighRoleProfileID]; !exists {
			return fmt.Errorf("authorization policy %q references unknown high auth profile %q", policy.ID, policy.HighRoleProfileID)
		}
		actionMethod := strings.ToUpper(strings.TrimSpace(policy.Method))
		cleanupMethod := strings.ToUpper(strings.TrimSpace(policy.CleanupMethod))
		if actionMethod == http.MethodGet || actionMethod == http.MethodHead ||
			cleanupMethod == http.MethodGet || cleanupMethod == http.MethodHead {
			return fmt.Errorf("authorization policy %q state action and cleanup must use write methods", policy.ID)
		}
		for name, rawURL := range map[string]string{"state_url": policy.StateURL, "cleanup_url": policy.CleanupURL} {
			parsed, parseErr := url.ParseRequestURI(rawURL)
			if parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
				return fmt.Errorf("authorization policy %q has invalid %s", policy.ID, name)
			}
		}
	}
	seenObjectPolicies := make(map[string]struct{}, len(c.ObjectAuthorizationPolicies))
	for index, policy := range c.ObjectAuthorizationPolicies {
		if strings.TrimSpace(policy.ID) == "" || strings.TrimSpace(policy.URLContains) == "" ||
			strings.TrimSpace(policy.Method) == "" || strings.TrimSpace(policy.Parameter) == "" ||
			strings.TrimSpace(policy.OwnerRoleProfileID) == "" || strings.TrimSpace(policy.ForeignRoleProfileID) == "" ||
			strings.TrimSpace(policy.ExpectedPolicy) == "" || len(policy.ResourceValues) == 0 ||
			!policy.RequireAnonymousDeny {
			return fmt.Errorf("object_authorization_policies[%d] requires ownership roles, resource values, expected policy and anonymous denial", index)
		}
		if _, duplicate := seenObjectPolicies[policy.ID]; duplicate {
			return fmt.Errorf("duplicate object authorization policy id: %q", policy.ID)
		}
		seenObjectPolicies[policy.ID] = struct{}{}
		if policy.OwnerRoleProfileID == policy.ForeignRoleProfileID {
			return fmt.Errorf("object authorization policy %q must use distinct owner/foreign roles", policy.ID)
		}
		if !recordedReadMethod(policy.Method) {
			return fmt.Errorf("object authorization policy %q must use a read-only method; use an authorization state/cleanup policy for writes", policy.ID)
		}
		if _, exists := roleProfileIDs[policy.OwnerRoleProfileID]; !exists {
			return fmt.Errorf("object authorization policy %q references unknown owner role %q", policy.ID, policy.OwnerRoleProfileID)
		}
		if _, exists := roleProfileIDs[policy.ForeignRoleProfileID]; !exists {
			return fmt.Errorf("object authorization policy %q references unknown foreign role %q", policy.ID, policy.ForeignRoleProfileID)
		}
		switch strings.ToLower(strings.TrimSpace(policy.Location)) {
		case "", "query", "path", "json", "graphql", "form":
		default:
			return fmt.Errorf("object authorization policy %q has unsupported parameter location %q", policy.ID, policy.Location)
		}
	}
	if c.OASTSelfHosted != nil {
		selfHosted := c.OASTSelfHosted
		if strings.TrimSpace(selfHosted.Domain) == "" {
			return fmt.Errorf("oast_self_hosted.domain is required")
		}
		if selfHosted.HTTPAddr == "" && selfHosted.HTTPSAddr == "" && selfHosted.DNSAddr == "" &&
			selfHosted.SMTPAddr == "" && selfHosted.LDAPAddr == "" {
			return fmt.Errorf("oast_self_hosted requires at least one listener address")
		}
		if (selfHosted.TLSCertFile == "") != (selfHosted.TLSKeyFile == "") {
			return fmt.Errorf("oast_self_hosted TLS certificate and key must be configured together")
		}
	}
	seenRacePolicies := make(map[string]struct{}, len(c.RaceProofPolicies))
	for index, policy := range c.RaceProofPolicies {
		if policy.ID == "" || policy.URLContains == "" || policy.AuthProfileID == "" ||
			policy.Action.Method == "" || policy.Action.URL == "" || policy.State.Method == "" ||
			policy.State.URL == "" || policy.Cleanup.Method == "" || policy.Cleanup.URL == "" ||
			policy.TransactionIDExpression == "" {
			return fmt.Errorf("race_proof_policies[%d] is incomplete", index)
		}
		if _, duplicate := seenRacePolicies[policy.ID]; duplicate {
			return fmt.Errorf("duplicate race proof policy id: %q", policy.ID)
		}
		seenRacePolicies[policy.ID] = struct{}{}
		if _, exists := authProfileIDs[policy.AuthProfileID]; !exists {
			return fmt.Errorf("race policy %q references unknown auth profile %q", policy.ID, policy.AuthProfileID)
		}
		if !recordedWriteMethod(policy.Action.Method) || !recordedReadMethod(policy.State.Method) ||
			!recordedWriteMethod(policy.Cleanup.Method) {
			return fmt.Errorf("race policy %q requires write action/cleanup and read-only state request", policy.ID)
		}
		if policy.SequentialRuns != 0 && (policy.SequentialRuns < 5 || policy.SequentialRuns > 10) {
			return fmt.Errorf("race policy %q sequential_runs must be between 5 and 10", policy.ID)
		}
		if policy.ConcurrentRuns != 0 && (policy.ConcurrentRuns < 2 || policy.ConcurrentRuns > 20) {
			return fmt.Errorf("race policy %q concurrent_runs must be between 2 and 20", policy.ID)
		}
	}
	seenBusinessPolicies := make(map[string]struct{}, len(c.BusinessLogicProofPolicies))
	for index, policy := range c.BusinessLogicProofPolicies {
		if policy.ID == "" || policy.URLContains == "" || policy.AuthProfileID == "" ||
			policy.ExpectedInvariant == "" || policy.NativeAction.Method == "" || policy.NativeAction.URL == "" ||
			policy.ManipulatedAction.Method == "" || policy.ManipulatedAction.URL == "" ||
			policy.NegativeControl.Method == "" || policy.NegativeControl.URL == "" ||
			policy.State.Method == "" || policy.State.URL == "" || policy.Cleanup.Method == "" ||
			policy.Cleanup.URL == "" || policy.TransactionIDExpression == "" ||
			policy.StateValueExpression == "" || policy.ForbiddenValue == "" {
			return fmt.Errorf("business_logic_proof_policies[%d] is incomplete", index)
		}
		if _, duplicate := seenBusinessPolicies[policy.ID]; duplicate {
			return fmt.Errorf("duplicate business logic proof policy id: %q", policy.ID)
		}
		seenBusinessPolicies[policy.ID] = struct{}{}
		if _, exists := authProfileIDs[policy.AuthProfileID]; !exists {
			return fmt.Errorf("business logic policy %q references unknown auth profile %q", policy.ID, policy.AuthProfileID)
		}
		if !recordedWriteMethod(policy.NativeAction.Method) ||
			!recordedWriteMethod(policy.ManipulatedAction.Method) ||
			!recordedWriteMethod(policy.NegativeControl.Method) ||
			!recordedReadMethod(policy.State.Method) ||
			!recordedWriteMethod(policy.Cleanup.Method) {
			return fmt.Errorf("business logic policy %q requires write actions/cleanup and read-only state request", policy.ID)
		}
	}
	if err := validateStatefulSecurityPolicies("account_recovery_proof_policies", c.AccountRecoveryProofPolicies, authProfileIDs); err != nil {
		return err
	}
	if err := validateStatefulSecurityPolicies("webhook_proof_policies", c.WebhookProofPolicies, authProfileIDs); err != nil {
		return err
	}
	if err := validateStatefulSecurityPolicies("csrf_proof_policies", c.CSRFProofPolicies, authProfileIDs); err != nil {
		return err
	}
	for index, policy := range c.CSRFProofPolicies {
		if strings.TrimSpace(policy.AuthProfileID) == "" {
			return fmt.Errorf("csrf_proof_policies[%d] requires an isolated auth profile", index)
		}
	}
	seenSessionPolicies := make(map[string]struct{}, len(c.SessionLifecycleProofPolicies))
	for index, policy := range c.SessionLifecycleProofPolicies {
		if policy.ID == "" || policy.URLContains == "" || policy.AuthProfileID == "" ||
			policy.ExpectedInvariant == "" || !policy.DisposableCredential || policy.Logout.URL == "" ||
			policy.ProtectedResource.URL == "" || !recordedWriteMethod(policy.Logout.Method) ||
			!recordedReadMethod(policy.ProtectedResource.Method) {
			return fmt.Errorf("session_lifecycle_proof_policies[%d] requires a disposable credential, write logout, and read-only protected resource", index)
		}
		if _, duplicate := seenSessionPolicies[policy.ID]; duplicate {
			return fmt.Errorf("duplicate session lifecycle proof policy id: %q", policy.ID)
		}
		seenSessionPolicies[policy.ID] = struct{}{}
		if _, exists := authProfileIDs[policy.AuthProfileID]; !exists {
			return fmt.Errorf("session lifecycle policy %q references unknown auth profile %q", policy.ID, policy.AuthProfileID)
		}
		for name, rawURL := range map[string]string{"logout": policy.Logout.URL, "protected_resource": policy.ProtectedResource.URL} {
			parsed, parseErr := url.ParseRequestURI(rawURL)
			if parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
				return fmt.Errorf("session lifecycle policy %q has invalid %s URL", policy.ID, name)
			}
		}
	}
	for index, policy := range c.FileUploadProofPolicies {
		if policy.ID == "" || policy.URLContains == "" || policy.CleanupMethod == "" || policy.CleanupURL == "" {
			return fmt.Errorf("file_upload_proof_policies[%d] is incomplete", index)
		}
		if strings.EqualFold(policy.CleanupMethod, http.MethodGet) ||
			strings.EqualFold(policy.CleanupMethod, http.MethodHead) {
			return fmt.Errorf("file upload cleanup policy %q must use a write method", policy.ID)
		}
		if strings.Contains(policy.CleanupURL, "{{location}}") {
			return fmt.Errorf("file upload cleanup policy %q must be resolvable before upload; {{location}} is not allowed", policy.ID)
		}
	}
	for index, policy := range c.CacheDeceptionProofPolicies {
		if policy.ID == "" || policy.URLContains == "" || policy.PrivateCanary == "" {
			return fmt.Errorf("cache_deception_proof_policies[%d] is incomplete", index)
		}
	}
	for index, policy := range c.HPPProofPolicies {
		if policy.ID == "" || policy.URLContains == "" || policy.AuthProfileID == "" ||
			policy.ExpectedInvariant == "" || policy.NativeValue == "" || len(policy.DuplicateValues) < 2 ||
			policy.State.URL == "" || policy.State.Method == "" || policy.Cleanup.URL == "" ||
			policy.Cleanup.Method == "" || policy.StateValueExpression == "" || policy.ForbiddenValue == "" {
			return fmt.Errorf("hpp_proof_policies[%d] is incomplete", index)
		}
	}
	return nil
}

func validateStatefulSecurityPolicies(field string, policies []StatefulSecurityProofPolicy,
	authProfileIDs map[string]struct{}) error {
	seen := make(map[string]struct{}, len(policies))
	for index, policy := range policies {
		if strings.TrimSpace(policy.ID) == "" || strings.TrimSpace(policy.URLContains) == "" ||
			strings.TrimSpace(policy.ExpectedInvariant) == "" || policy.Action.Method == "" || policy.Action.URL == "" ||
			policy.NegativeControl.Method == "" || policy.NegativeControl.URL == "" ||
			policy.State.Method == "" || policy.State.URL == "" || policy.Cleanup.Method == "" || policy.Cleanup.URL == "" {
			return fmt.Errorf("%s[%d] is incomplete", field, index)
		}
		if _, duplicate := seen[policy.ID]; duplicate {
			return fmt.Errorf("duplicate %s id: %q", field, policy.ID)
		}
		seen[policy.ID] = struct{}{}
		if profileID := strings.TrimSpace(policy.AuthProfileID); profileID != "" {
			if _, exists := authProfileIDs[profileID]; !exists {
				return fmt.Errorf("%s %q references unknown auth profile %q", field, policy.ID, profileID)
			}
		}
		if !recordedWriteMethod(policy.Action.Method) || !recordedWriteMethod(policy.NegativeControl.Method) ||
			!recordedReadMethod(policy.State.Method) || !recordedWriteMethod(policy.Cleanup.Method) {
			return fmt.Errorf("%s %q requires write action/negative control/cleanup and read-only state request", field, policy.ID)
		}
		for name, request := range map[string]RecordedRequest{
			"action": policy.Action, "negative_control": policy.NegativeControl,
			"state": policy.State, "cleanup": policy.Cleanup,
		} {
			parsed, parseErr := url.ParseRequestURI(request.URL)
			if parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
				return fmt.Errorf("%s %q has invalid %s URL", field, policy.ID, name)
			}
		}
	}
	return nil
}

func recordedReadMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead:
		return true
	default:
		return false
	}
}

func recordedWriteMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func (c ScanConfig) MarshalJSON() ([]byte, error) {
	type Alias ScanConfig
	aux := struct {
		Alias
		TimeBudget string `json:"time_budget"`
	}{
		Alias:      Alias(c),
		TimeBudget: c.TimeBudget.String(),
	}
	return json.Marshal(aux)
}

func (c *ScanConfig) UnmarshalJSON(data []byte) error {
	type Alias ScanConfig
	aux := struct {
		*Alias
		TimeBudget string `json:"time_budget"`
	}{
		Alias: (*Alias)(c),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.TimeBudget != "" {
		d, err := time.ParseDuration(aux.TimeBudget)
		if err != nil {
			return fmt.Errorf("invalid time_budget: %w", err)
		}
		c.TimeBudget = d
	}
	return nil
}

func Save(path string, cfg ScanConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	// Best-effort permission tighten; some FSes (FAT32/network) may not support it.
	_ = os.Chmod(path, 0o600)
	return nil
}

func Load(path string) (ScanConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ScanConfig{}, err
	}
	var cfg ScanConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return ScanConfig{}, err
	}
	if err := cfg.Validate(); err != nil {
		return ScanConfig{}, err
	}
	return cfg, nil
}

func (c ScanConfig) PayloadBudgetLimit() int {
	switch c.PayloadBudget {
	case PayloadBudgetLow:
		return 5
	case PayloadBudgetMedium:
		return 15
	case PayloadBudgetHigh:
		return 50
	case PayloadBudgetUnlimited:
		return -1
	default:
		return -1 // unlimited — thorough scanning is the default
	}
}

func NormalizeDomain(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return ""
	}
	wildcard := strings.HasPrefix(d, "*.")
	if wildcard {
		d = strings.TrimPrefix(d, "*.")
	}
	if strings.Contains(d, "://") {
		if u, err := url.Parse(d); err == nil && u.Host != "" {
			host := strings.ToLower(u.Host)
			if (u.Scheme == "http" && strings.HasSuffix(host, ":80")) ||
				(u.Scheme == "https" && strings.HasSuffix(host, ":443")) {
				d = u.Hostname()
			} else {
				d = host
			}
		}
	} else if strings.ContainsAny(d, "/?#") {
		if u, err := url.Parse("https://" + d); err == nil && u.Host != "" {
			d = u.Host
		}
	}
	d = strings.TrimPrefix(d, ".")
	if wildcard && d != "" {
		return "*." + d
	}
	return d
}

// RedactedForStorage returns a copy of ScanConfig with sensitive credentials, passwords, and tokens masked.
func (c ScanConfig) RedactedForStorage() ScanConfig {
	redacted := c
	if redacted.LoginCredentials != nil && redacted.LoginCredentials.Password != "" {
		credentials := *redacted.LoginCredentials
		redacted.LoginCredentials = &credentials
		redacted.LoginCredentials.Password = "[REDACTED]"
	}
	if len(redacted.Authentication) > 0 {
		auth := make(map[string]string, len(redacted.Authentication))
		for k := range redacted.Authentication {
			auth[k] = "[REDACTED]"
		}
		redacted.Authentication = auth
	}
	if len(redacted.SessionCookies) > 0 {
		cookies := make(map[string]string, len(redacted.SessionCookies))
		for k := range redacted.SessionCookies {
			cookies[k] = "[REDACTED]"
		}
		redacted.SessionCookies = cookies
	}
	if len(redacted.ApiKeys) > 0 {
		keys := make(map[string]string, len(redacted.ApiKeys))
		for k := range redacted.ApiKeys {
			keys[k] = "[REDACTED]"
		}
		redacted.ApiKeys = keys
	}
	if len(redacted.CustomHeaders) > 0 {
		headers := make(map[string]string, len(redacted.CustomHeaders))
		for k := range redacted.CustomHeaders {
			headers[k] = "[REDACTED]"
		}
		redacted.CustomHeaders = headers
	}
	if len(redacted.AuthProfiles) > 0 {
		redacted.AuthProfiles = append([]AuthProfile(nil), redacted.AuthProfiles...)
		for index := range redacted.AuthProfiles {
			if len(redacted.AuthProfiles[index].Headers) > 0 {
				headers := make(map[string]string, len(redacted.AuthProfiles[index].Headers))
				for key := range redacted.AuthProfiles[index].Headers {
					headers[key] = "[REDACTED]"
				}
				redacted.AuthProfiles[index].Headers = headers
			}
			if len(redacted.AuthProfiles[index].Cookies) > 0 {
				cookies := make(map[string]string, len(redacted.AuthProfiles[index].Cookies))
				for key := range redacted.AuthProfiles[index].Cookies {
					cookies[key] = "[REDACTED]"
				}
				redacted.AuthProfiles[index].Cookies = cookies
			}
		}
	}
	for index := range redacted.AuthorizationPolicies {
		if redacted.AuthorizationPolicies[index].ActionBody != "" {
			redacted.AuthorizationPolicies[index].ActionBody = "[REDACTED]"
		}
		if redacted.AuthorizationPolicies[index].CleanupBody != "" {
			redacted.AuthorizationPolicies[index].CleanupBody = "[REDACTED]"
		}
	}
	redactRecorded := func(request *RecordedRequest) {
		if request.Body != "" {
			request.Body = "[REDACTED]"
		}
		if len(request.Headers) > 0 {
			headers := make(map[string]string, len(request.Headers))
			for key := range request.Headers {
				headers[key] = "[REDACTED]"
			}
			request.Headers = headers
		}
	}
	redacted.RaceProofPolicies = append([]RaceProofPolicy(nil), redacted.RaceProofPolicies...)
	for index := range redacted.RaceProofPolicies {
		redactRecorded(&redacted.RaceProofPolicies[index].Action)
		redactRecorded(&redacted.RaceProofPolicies[index].State)
		redactRecorded(&redacted.RaceProofPolicies[index].Cleanup)
	}
	redacted.BusinessLogicProofPolicies = append([]BusinessLogicProofPolicy(nil), redacted.BusinessLogicProofPolicies...)
	for index := range redacted.BusinessLogicProofPolicies {
		redactRecorded(&redacted.BusinessLogicProofPolicies[index].NativeAction)
		redactRecorded(&redacted.BusinessLogicProofPolicies[index].ManipulatedAction)
		redactRecorded(&redacted.BusinessLogicProofPolicies[index].NegativeControl)
		redactRecorded(&redacted.BusinessLogicProofPolicies[index].State)
		redactRecorded(&redacted.BusinessLogicProofPolicies[index].Cleanup)
	}
	redacted.AccountRecoveryProofPolicies = redactStatefulSecurityPolicies(redacted.AccountRecoveryProofPolicies)
	redacted.WebhookProofPolicies = redactStatefulSecurityPolicies(redacted.WebhookProofPolicies)
	redacted.CSRFProofPolicies = redactStatefulSecurityPolicies(redacted.CSRFProofPolicies)
	redacted.SessionLifecycleProofPolicies = append([]SessionLifecycleProofPolicy(nil), redacted.SessionLifecycleProofPolicies...)
	for index := range redacted.SessionLifecycleProofPolicies {
		redactRecorded(&redacted.SessionLifecycleProofPolicies[index].Logout)
		redactRecorded(&redacted.SessionLifecycleProofPolicies[index].ProtectedResource)
	}
	redacted.HPPProofPolicies = append([]HPPProofPolicy(nil), redacted.HPPProofPolicies...)
	for index := range redacted.HPPProofPolicies {
		redactRecorded(&redacted.HPPProofPolicies[index].State)
		redactRecorded(&redacted.HPPProofPolicies[index].Cleanup)
	}
	if len(redacted.JWTExpiredTokens) > 0 {
		redacted.JWTExpiredTokens = []string{"[REDACTED]"}
	}
	return redacted
}

func redactStatefulSecurityPolicies(policies []StatefulSecurityProofPolicy) []StatefulSecurityProofPolicy {
	redacted := append([]StatefulSecurityProofPolicy(nil), policies...)
	for index := range redacted {
		for _, request := range []*RecordedRequest{
			&redacted[index].Action, &redacted[index].NegativeControl, &redacted[index].State, &redacted[index].Cleanup,
		} {
			if request.Body != "" {
				request.Body = "[REDACTED]"
			}
			if len(request.Headers) > 0 {
				headers := make(map[string]string, len(request.Headers))
				for key := range request.Headers {
					headers[key] = "[REDACTED]"
				}
				request.Headers = headers
			}
		}
	}
	return redacted
}
