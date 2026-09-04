package modules

import (
	"context"
	"strings"
)

var recoveryRouteKeywords = []string{
	"forgot-password", "forgot_password", "forgotpassword",
	"reset-password", "reset_password", "resetpassword",
	"recovery", "account-recovery", "recover",
	"change-password", "change_password", "changepassword",
	"update-password", "update_password", "updatepassword",
	"change-email", "change_email", "changeemail",
}

func (r *Runner) runAccountRecovery(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("account_recovery", target); !ok {
		r.emitSkip("account_recovery", target, reason)
		return nil
	}
	if !isAccountRecoveryRoute(strings.ToLower(strings.TrimSpace(target.EndpointURL))) {
		return nil
	}
	return r.runStatefulSecurityProof(ctx, "account_recovery", target,
		r.cfg.AccountRecoveryProofPolicies, statefulSecurityFinding{
			Signal: "recovery_state_mutation", Variant: "recorded_recovery_invariant",
			Title:       "Account recovery invariant bypass changed account state",
			Description: "the unsafe recovery action changed independently observed account state, the negative control did not, and cleanup restored the original snapshot.",
			Severity:    "Critical",
		})
}

func isAccountRecoveryRoute(urlLower string) bool {
	for _, keyword := range recoveryRouteKeywords {
		if strings.Contains(urlLower, keyword) {
			return true
		}
	}
	return false
}
