package testlab

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/akha-security/akca/engine/internal/modules"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/reflection"
)

const ParityNegativeVariants = 16

func (p *pipeline) labModuleTargets(runner *modules.Runner) []modules.ScanTarget {
	base := strings.TrimRight(p.lab.Server.URL, "/")
	essential := []modules.ScanTarget{
		{EndpointURL: base + "/search", Method: "GET", Parameter: "q", Location: "query"},
		{EndpointURL: base + "/api/users", Method: "GET", Parameter: "id", Location: "query"},
		{EndpointURL: base + "/redirect", Method: "GET", Parameter: "url", Location: "query"},
		{EndpointURL: base + "/api/fetch", Method: "GET", Parameter: "url", Location: "query"},
		{EndpointURL: base + "/download", Method: "GET", Parameter: "file", Location: "query"},
		{EndpointURL: base + "/coupon/claim", Method: "GET", Parameter: "claim", Location: "query"},
		{EndpointURL: base + "/graphql", Method: "POST", Parameter: "body", Location: "body"},
		{EndpointURL: base + "/xml", Method: "POST", Parameter: "body", Location: "body",
			Profile: reflection.ReflectionProfile{ContentType: "application/xml"}},
		{EndpointURL: base + "/profile", Method: "GET", Parameter: "", Location: "query"},
		{EndpointURL: base + "/actuator/health", Method: "GET", Parameter: "", Location: "query"},
		{EndpointURL: base + "/waf-probe", Method: "GET", Parameter: "x", Location: "query"},
		{EndpointURL: base + "/static/app.js", Method: "GET", Parameter: "", Location: "query"},
	}

	seen := map[string]struct{}{}
	var out []modules.ScanTarget
	add := func(t modules.ScanTarget) {
		key := t.EndpointURL + "|" + t.Method + "|" + t.Parameter
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		paramKey := t.EndpointURL + "::" + t.Parameter
		if raw, _ := p.db.LoadPayloadGenerationJSON(paramKey); raw != "" {
			var gen payloadgen.GenerationResult
			if json.Unmarshal([]byte(raw), &gen) == nil {
				t.Payloads = gen
			}
		}
		if len(t.Payloads.Payloads) == 0 {
			t.Payloads = labFallbackPayloads(t)
		} else {
			t.Payloads = mergeEssentialLabPayloads(t.Payloads, labFallbackPayloads(t))
		}
		if strings.Contains(strings.ToLower(t.EndpointURL), "/api/users") ||
			strings.Contains(strings.ToLower(t.EndpointURL), "/api/fetch") {
			t.Payloads = labFallbackPayloads(t)
		}
		out = append(out, t)
	}

	for _, t := range essential {
		add(t)
	}
	for i := 0; i < p.parityCorpusSize; i++ {
		add(modules.ScanTarget{EndpointURL: fmt.Sprintf("%s/parity/safe/search/%02d", base, i), Method: "GET", Parameter: "q", Location: "query"})
		add(modules.ScanTarget{EndpointURL: fmt.Sprintf("%s/parity/safe/api/users/%02d", base, i), Method: "GET", Parameter: "id", Location: "query"})
		add(modules.ScanTarget{EndpointURL: fmt.Sprintf("%s/parity/safe/api/fetch/%02d", base, i), Method: "GET", Parameter: "url", Location: "query"})
		add(modules.ScanTarget{EndpointURL: fmt.Sprintf("%s/parity/safe/download/%02d", base, i), Method: "GET", Parameter: "file", Location: "query"})
	}

	if fromDB, err := runner.LoadTargetsFromDB(40); err == nil {
		want := []string{"/search", "/api/users", "/redirect", "/graphql", "/api/fetch", "/download", "/coupon", "/actuator", "/profile", "/waf-probe", "/static/"}
		for _, t := range fromDB {
			for _, frag := range want {
				if strings.Contains(t.EndpointURL, frag) {
					add(t)
					break
				}
			}
		}
	}
	return out
}

func labFallbackPayloads(target modules.ScanTarget) payloadgen.GenerationResult {
	path := strings.ToLower(target.EndpointURL)
	var payloads []payloadgen.Payload
	if strings.Contains(path, "/search") || strings.Contains(path, "/waf-probe") {
		payloads = append(payloads,
			payloadgen.Payload{VulnClass: "xss", Value: `<script>alert(1)</script>`, Variant: "reflected", Priority: 10, BudgetCost: 1},
			payloadgen.Payload{VulnClass: "xss", Value: `"><img src=x onerror=alert(1)>`, Variant: "encoded", Priority: 9, BudgetCost: 1},
		)
	}
	if strings.Contains(path, "/api/users") {
		payloads = append(payloads,
			payloadgen.Payload{VulnClass: "sqli", Value: `'`, Variant: "error_single_quote", ExpectedSignal: "sql_error", Priority: 11, BudgetCost: 1},
			payloadgen.Payload{VulnClass: "sqli", Value: `' OR '1'='1`, Variant: "error", ExpectedSignal: "sql_error", Priority: 10, BudgetCost: 1},
		)
	}
	if strings.Contains(path, "/api/fetch") {
		payloads = append(payloads,
			payloadgen.Payload{VulnClass: "ssrf", Value: `http://169.254.169.254/latest/meta-data/`, Variant: "metadata", ExpectedSignal: "cloud_metadata", Priority: 10, BudgetCost: 1},
			payloadgen.Payload{VulnClass: "ssrf", Value: `http://2852039166/latest/meta-data/`, Variant: "metadata_decimal", ExpectedSignal: "aws_metadata", Priority: 9, BudgetCost: 1},
		)
	}
	if strings.Contains(path, "/download") {
		payloads = append(payloads,
			payloadgen.Payload{VulnClass: "lfi", Value: `../../../../etc/passwd`, Variant: "traversal", ExpectedSignal: "path_traversal", Priority: 10, BudgetCost: 1},
		)
	}
	if strings.Contains(path, "/xml") {
		payloads = append(payloads,
			payloadgen.Payload{VulnClass: "xxe", Value: `<!DOCTYPE foo [<!ENTITY xxe "AKCA_XXE_TEST">]><foo>&xxe;</foo>`, Variant: "classic", ExpectedSignal: "classic_entity", Priority: 10, BudgetCost: 1},
		)
	}
	return payloadgen.GenerationResult{EndpointURL: target.EndpointURL, Parameter: target.Parameter, Payloads: payloads}
}

func mergeEssentialLabPayloads(base, fallback payloadgen.GenerationResult) payloadgen.GenerationResult {
	if len(fallback.Payloads) == 0 {
		return base
	}
	hasClass := map[string]struct{}{}
	for _, p := range base.Payloads {
		hasClass[p.VulnClass] = struct{}{}
	}
	out := base
	for _, p := range fallback.Payloads {
		if _, ok := hasClass[p.VulnClass]; ok {
			continue
		}
		out.Payloads = append(out.Payloads, p)
		hasClass[p.VulnClass] = struct{}{}
	}
	return out
}
