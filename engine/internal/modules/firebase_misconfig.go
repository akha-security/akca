package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	rtdbHostRe    = regexp.MustCompile(`(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.firebaseio\.com`)
	storageHostRe = regexp.MustCompile(`(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])\.appspot\.com`)
)

var rtdbCommonPaths = []string{
	"",
	"users",
	"user",
	"profiles",
	"config",
	"settings",
	"admin",
	"tokens",
	"accounts",
}

func (r *Runner) runFirebaseMisconfig(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("firebase_misconfig", target); !ok {
		r.emitSkip("firebase_misconfig", target, reason)
		return nil
	}

	baseline, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}

	body := baseline.Response.Body
	var out []ModuleFinding

	// 1. Scan for Firebase Realtime Database
	dbMatches := rtdbHostRe.FindAllStringSubmatch(body, 10)
	dbSeen := map[string]struct{}{}
	for _, m := range dbMatches {
		if len(m) < 2 {
			continue
		}
		dbName := m[1]
		if _, ok := dbSeen[dbName]; ok {
			continue
		}
		dbSeen[dbName] = struct{}{}

		dbBaseURL := fmt.Sprintf("https://%s.firebaseio.com", dbName)
		for _, subpath := range rtdbCommonPaths {
			if ctx.Err() != nil {
				break
			}
			targetPath := "/.json"
			if subpath != "" {
				targetPath = "/" + subpath + ".json"
			}
			dbURL := dbBaseURL + targetPath + "?shallow=true"
			if !r.scope.IsInScope(dbURL) {
				continue
			}

			rr, err := r.client.Do(ctx, "GET", dbURL, nil, nil)
			if err != nil || rr.Response.StatusCode != 200 {
				continue
			}

			respBody := strings.TrimSpace(rr.Response.Body)
			if !isValidRTDBData(respBody) {
				continue
			}

			// Re-verify once to confirm stability
			reRR, reErr := r.client.Do(ctx, "GET", dbURL, nil, nil)
			if reErr != nil || reRR.Response.StatusCode != 200 || !isValidRTDBData(reRR.Response.Body) {
				continue
			}

			signal := "firebase_rtdb_public_read"
			p := defaultPayload("firebase_misconfig", signal, dbURL, signal)
			f := r.verifyAndBuild(ctx, "firebase_misconfig", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Severity = "high"
				f.Title = fmt.Sprintf("Firebase Realtime Database Public Read (%s)", dbName)
				if subpath != "" {
					f.Title = fmt.Sprintf("Firebase Realtime Database Public Read (%s/%s)", dbName, subpath)
				}
				f.Description = fmt.Sprintf("Firebase Realtime Database at '%s' is configured with open read rules (publicly readable without authentication).", dbURL)
				r.recordFinding(ctx, &out, f, "firebase_misconfig", signal)
				break // Stop on first readable path per database
			}
		}
	}

	// 2. Scan for Firebase Storage Buckets
	storageMatches := storageHostRe.FindAllStringSubmatch(body, 10)
	storageSeen := map[string]struct{}{}
	for _, m := range storageMatches {
		if len(m) < 2 {
			continue
		}
		bucketName := m[1] + ".appspot.com"
		if _, ok := storageSeen[bucketName]; ok {
			continue
		}
		storageSeen[bucketName] = struct{}{}

		storageAPIURL := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o/", url.PathEscape(bucketName))
		if !r.scope.IsInScope(storageAPIURL) {
			continue
		}

		rr, err := r.client.Do(ctx, "GET", storageAPIURL, nil, nil)
		if err != nil || rr.Response.StatusCode != 200 {
			continue
		}

		respBody := strings.TrimSpace(rr.Response.Body)
		if strings.Contains(respBody, `"items"`) || strings.Contains(respBody, `"name"`) && strings.Contains(respBody, `"bucket"`) {
			signal := "firebase_storage_public_listing"
			p := defaultPayload("firebase_misconfig", signal, storageAPIURL, signal)
			f := r.verifyAndBuild(ctx, "firebase_misconfig", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Severity = "high"
				f.Title = fmt.Sprintf("Firebase Storage Bucket Public Object Listing (%s)", bucketName)
				f.Description = fmt.Sprintf("Firebase Storage bucket '%s' is publicly readable, exposing stored application objects and uploads.", bucketName)
				r.recordFinding(ctx, &out, f, "firebase_misconfig", signal)
			}
		}
	}

	return out
}

func isValidRTDBData(body string) bool {
	if body == "" || body == "null" || body == "{}" || body == "[]" {
		return false
	}
	if strings.Contains(body, "Permission denied") || strings.Contains(body, "<html") || strings.Contains(body, "<!DOCTYPE") {
		return false
	}
	var v interface{}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return false
	}
	switch t := v.(type) {
	case map[string]interface{}:
		if len(t) == 0 {
			return false
		}
		if _, hasErr := t["error"]; hasErr && len(t) == 1 {
			return false
		}
		return true
	case []interface{}:
		return len(t) > 0
	default:
		return false
	}
}

func firebaseSignalConfirmed(signal, body string, status int) bool {
	if status != 200 {
		return false
	}
	switch signal {
	case "firebase_rtdb_public_read":
		return isValidRTDBData(strings.TrimSpace(body))
	case "firebase_storage_public_listing":
		return strings.Contains(body, `"items"`) ||
			(strings.Contains(body, `"name"`) && strings.Contains(body, `"bucket"`))
	default:
		return false
	}
}
