package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

func (r *Runner) runSaaSExposure(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("saas_exposure", target); !ok {
		r.emitSkip("saas_exposure", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	origin := u.Scheme + "://" + u.Host

	baseline, baselineErr := r.cachedEmptyProbe(ctx, target)
	if baselineErr != nil {
		return nil
	}

	var out []ModuleFinding

	// 1. ServiceNow Unauthenticated Table API Exposure
	snEndpoints := []struct {
		table string
		label string
	}{
		{"sys_user", "User Table"},
		{"kb_knowledge", "Knowledge Base Table"},
		{"incident", "Incident Ticket Table"},
	}

	for _, sn := range snEndpoints {
		snURL := origin + "/api/now/table/" + sn.table + "?sysparm_limit=2"
		if !r.scope.IsInScope(snURL) {
			continue
		}

		rr, err := r.client.Do(ctx, "GET", snURL, nil, nil)
		if err == nil && rr.Response.StatusCode == 200 {
			body := rr.Response.Body
			if strings.Contains(body, `"result"`) && (strings.Contains(body, `"sys_id"`) || strings.Contains(body, `"user_name"`)) {
				signal := "servicenow_table_exposure"
				p := defaultPayload("saas_exposure", signal, snURL, signal)
				f := r.verifyAndBuild(ctx, "saas_exposure", target, p, baseline, rr, signal, false, false, "", "")
				if f != nil {
					f.Severity = "high"
					f.Title = fmt.Sprintf("ServiceNow Unauthenticated Data Exposure (%s)", sn.label)
					f.Description = fmt.Sprintf("ServiceNow Table API for '%s' is accessible without credentials, leaking organizational records.", sn.table)
					r.recordFinding(ctx, &out, f, "saas_exposure", signal)
				}
			}
		}
	}

	// 2. Salesforce Aura Guest Access Exposure
	auraURL := origin + "/aura?r=0"
	if r.scope.IsInScope(auraURL) {
		auraPayload := `message={"actions":[{"id":"1;a","descriptor":"serviceComponent://ui.global.components.one.one/ACTION$getConfig","callingDescriptor":"UNKNOWN","params":{}}]}`
		headers := map[string]string{
			"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
		}
		rr, err := r.client.Do(ctx, "POST", auraURL, []byte(auraPayload), headers)
		if err == nil && rr.Response.StatusCode == 200 {
			body := rr.Response.Body
			if strings.Contains(body, `"actions"`) && strings.Contains(body, `"state":"SUCCESS"`) && strings.Contains(body, `"returnValue"`) {
				signal := "salesforce_aura_guest_exposure"
				p := defaultPayload("saas_exposure", signal, auraURL, signal)
				f := r.verifyAndBuild(ctx, "saas_exposure", target, p, baseline, rr, signal, false, false, "", "")
				if f != nil {
					f.Severity = "medium"
					f.Title = "Salesforce Aura Framework Guest Action Exposure"
					f.Description = "Salesforce Lightning Aura endpoint /aura responds to unauthenticated guest actions."
					r.recordFinding(ctx, &out, f, "saas_exposure", signal)
				}
			}
		}
	}

	return out
}

func saasExposureSignalConfirmed(signal, body string, status int) bool {
	if status != 200 {
		return false
	}
	switch signal {
	case "servicenow_table_exposure":
		return strings.Contains(body, `"result"`) &&
			(strings.Contains(body, `"sys_id"`) || strings.Contains(body, `"user_name"`))
	case "salesforce_aura_guest_exposure":
		return strings.Contains(body, `"actions"`) &&
			strings.Contains(body, `"state":"SUCCESS"`) &&
			strings.Contains(body, `"returnValue"`)
	default:
		return false
	}
}
