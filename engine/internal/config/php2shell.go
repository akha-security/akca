package config

import (
	"fmt"
	"net/url"
	"strings"
)

func (c ScanConfig) OnlyPHP2Shell() bool {
	return len(c.AllowedVulnerabilityClasses) == 1 && strings.EqualFold(strings.TrimSpace(c.AllowedVulnerabilityClasses[0]), "php2shell")
}

// DiscoveryMetadataOnly skips parameter mutations and reflection even when the
// explicitly enabled, isolated PHP2Shell lab check will run later.
func (c ScanConfig) DiscoveryMetadataOnly() bool {
	return c.PassiveMode || c.OnlyPHP2Shell()
}

func (c ScanConfig) ValidatePHP2ShellOptions() error {
	if !c.PHP2ShellActive {
		return nil
	}
	if c.PassiveMode {
		return fmt.Errorf("php2shell_active cannot run in passive mode")
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("php2shell_active requires at least one explicit target")
	}
	for _, raw := range c.Targets {
		normalized, err := NormalizeTargetURL(raw)
		if err != nil {
			return err
		}
		u, err := url.Parse(normalized)
		if err != nil || u.User != nil || strings.TrimSpace(u.Hostname()) == "" {
			return fmt.Errorf("PHP2Shell target must be an HTTP(S) URL without credentials")
		}
		if c.OnlyPHP2Shell() {
			if u.RawQuery != "" || u.Fragment != "" {
				return fmt.Errorf("PHP2Shell dedicated-mode target must not include a query or fragment")
			}
		}
	}
	return nil
}

// PHP2ShellLabURL validates the single URL used by the dedicated mode.
func (c ScanConfig) PHP2ShellLabURL() (string, error) {
	if len(c.Targets) != 1 {
		return "", fmt.Errorf("PHP2Shell active checks require one isolated lab target")
	}
	raw, err := NormalizeTargetURL(c.Targets[0])
	if err != nil {
		return "", err
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("PHP2Shell lab target must be an HTTP(S) URL without credentials, query or fragment")
	}
	if strings.TrimSpace(u.Hostname()) == "" {
		return "", fmt.Errorf("PHP2Shell active checks require a laboratory host")
	}
	return raw, nil
}

// PHP2ShellEndpointURL turns a host-only PHP2Shell target into the endpoint
// used by the module. The Nuclei check targets /index.php; callers should not
// have to append that path manually. Explicit non-root paths are preserved.
func PHP2ShellEndpointURL(raw string) (string, error) {
	normalized, err := NormalizeTargetURL(raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return "", err
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/index.php"
		u.RawPath = ""
	}
	return u.String(), nil
}

func restrictPHP2ShellDiscovery(cfg *ScanConfig) {
	if !cfg.OnlyPHP2Shell() {
		return
	}
	cfg.EnableFuzzing = false
	cfg.EnableOAST = false
	cfg.EnableWAFDetection = false
	cfg.Enable403BypassChecks = false
	cfg.EnableBusinessLogicChecks = false
	cfg.EnableRaceConditionTesting = false
	cfg.EnableSecondOrderTracking = false
	cfg.EnableHeadlessCrawler = false
	cfg.EnableBrowserWorkerPool = false
	cfg.EnableRuntimeSensor = false
	cfg.EnableJSAnalysis = false
	cfg.EnableWAFBypassHeaders = false
	cfg.WAFPayloadMode = WAFPayloadOff
	// Dedicated checks never expand to links, subdomains or redirect targets.
	cfg.FollowRedirects = false
	cfg.AutoAdoptSameRootRedirects = false
	cfg.IncludeLinkedAPISubdomains = false
	if cfg.PHP2ShellActive {
		cfg.MaxConcurrency = 1
		cfg.PerHostConcurrency = 1
		cfg.GlobalRateLimit = 1
		cfg.PerHostRateLimit = 1
		// No crawling expansion is necessary for a single explicitly chosen lab
		// path; the active module uses that exact URL only.
		cfg.MaxPages = 1
		cfg.MaxDepth = 1
	}
}
