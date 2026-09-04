package modules

import (
	"context"
	"strings"
)

var webhookRouteKeywords = []string{
	"/webhook", "/webhooks", "/callback", "/callbacks",
	"/hooks", "/events/incoming", "/notify", "/notifications/incoming",
	"/payment/callback", "/payments/callback", "/stripe/webhook",
	"/github/webhook", "/shopify/webhook",
}

func (r *Runner) runWebhookSecurity(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("webhook_security", target); !ok {
		r.emitSkip("webhook_security", target, reason)
		return nil
	}
	if !isWebhookRoute(strings.ToLower(strings.TrimSpace(target.EndpointURL))) {
		return nil
	}
	return r.runStatefulSecurityProof(ctx, "webhook_security", target,
		r.cfg.WebhookProofPolicies, statefulSecurityFinding{
			Signal: "unauthenticated_webhook_state_mutation", Variant: "recorded_unsigned_event",
			Title:       "Unsigned webhook event changed server state",
			Description: "the unsigned or forged event changed independently observed server state, the negative control did not, and cleanup restored the original snapshot.",
			Severity:    "Critical",
		})
}

func isWebhookRoute(urlLower string) bool {
	for _, keyword := range webhookRouteKeywords {
		if strings.Contains(urlLower, keyword) {
			return true
		}
	}
	return false
}
