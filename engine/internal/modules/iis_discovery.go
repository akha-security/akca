package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

// Suffixes and methods adapted from shortscan (IIS short filename enumeration by bitquark)
var iisPathSuffixes = []string{
	"/.aspx",
	"?aspxerrorpath=/",
	"/.aspx?aspxerrorpath=/",
	"/.ashx",
	"/.asmx",
	"/.axd",
	"/.soap",
	"/.vb",
	"/",
	"",
}

var iisHTTPMethods = []string{"OPTIONS", "DEBUG", "GET", "TRACE", "HEAD", "POST"}

// Common shortname prefixes to attempt extraction once vulnerability is confirmed
var iisCommonPrefixes = []string{
	"ADMIN", "BACKUP", "CONFIG", "SECRET", "PASSW", "DATABASE", "DATA", "UPLOAD",
	"LOGS", "LOG", "TEST", "WEB", "DEFAULT", "INDEX", "LOGIN", "API", "WS", "APP",
	"DEV", "STAGING", "INTERNAL", "PRIVATE", "USER", "AUTH", "TEMP", "CACHE",
}

const iisAlphanumChars = "JFKGOTMYVHSPCANDXLRWEBQUIZ8549176320-_()"

// High-value IIS target wordlist for autocomplete long name recovery
var iisWordlistEntries = []struct {
	full    string
	short83 string
}{
	{"web.config", "WEB~1.CON"},
	{"administrator.aspx", "ADMINI~1.ASP"},
	{"admin.aspx", "ADMIN~1.ASP"},
	{"default.aspx", "DEFAUL~1.ASP"},
	{"index.aspx", "INDEX~1.ASP"},
	{"login.aspx", "LOGIN~1.ASP"},
	{"global.asax", "GLOBAL~1.ASA"},
	{"elmah.axd", "ELMAH~1.AXD"},
	{"trace.axd", "TRACE~1.AXD"},
	{"conn.asp", "CONN~1.ASP"},
	{"database.mdf", "DATABA~1.MDF"},
	{"backup.zip", "BACKUP~1.ZIP"},
	{"packages.config", "PACKAG~1.CON"},
	{"appsettings.json", "APPSET~1.JSO"},
	{"swagger.json", "SWAGGE~1.JSO"},
}

func (r *Runner) runIISDiscovery(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("iis_discovery", target); !ok {
		r.emitSkip("iis_discovery", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil {
		return nil
	}
	origin := u.Scheme + "://" + u.Host

	var out []ModuleFinding

	basePath := "/"
	if u.Path != "" && u.Path != "/" {
		lastSlash := strings.LastIndex(u.Path, "/")
		if lastSlash > 0 {
			basePath = u.Path[:lastSlash]
		}
	}

	pathsToTest := []string{"/"}
	if basePath != "/" {
		pathsToTest = append(pathsToTest, basePath+"/")
	}

	// -------------------------------------------------------------------------
	// Stage 1: Calibration & Vulnerability Determination (shortscan methodology)
	// -------------------------------------------------------------------------
	type workingSetup struct {
		basePath  string
		method    string
		suffix    string
		statusPos int
		statusNeg int
		activeTilde int
		posRR     httpclient.RequestResponse
		negRR     httpclient.RequestResponse
		probeURL  string
	}

	var foundSetup *workingSetup

	for _, basePathPrefix := range pathsToTest {
		if foundSetup != nil {
			break
		}
		for _, suffix := range iisPathSuffixes {
			if foundSetup != nil {
				break
			}
			for _, method := range iisHTTPMethods {
				// 1. Send negative requests (*~7*, *~8*) which will never exist on Windows
				negURL1 := origin + basePathPrefix + "*~7*" + suffix
				negURL2 := origin + basePathPrefix + "*~8*" + suffix
				if !r.scope.IsInScope(negURL1) {
					continue
				}

				negRR1, nErr1 := r.client.Do(ctx, method, negURL1, nil, nil)
				if nErr1 != nil || negRR1.Response.StatusCode == 0 {
					continue
				}
				negRR2, nErr2 := r.client.Do(ctx, method, negURL2, nil, nil)
				if nErr2 != nil || negRR1.Response.StatusCode != negRR2.Response.StatusCode {
					// Negative response is unstable on this method/suffix combination
					continue
				}
				statusNeg := negRR1.Response.StatusCode

				// 2. Send positive requests (*~1*, *~2*) for potential existing 8.3 files
				for tildeIdx := 1; tildeIdx <= 4; tildeIdx++ {
					posURL := fmt.Sprintf("%s%s*~%d*%s", origin, basePathPrefix, tildeIdx, suffix)
					posRR, pErr := r.client.Do(ctx, method, posURL, nil, nil)
					if pErr != nil || posRR.Response.StatusCode == 0 {
						continue
					}

					statusPos := posRR.Response.StatusCode
					if statusPos != statusNeg {
						// FP Guard 1: Double check with *~0* to rule out rate limiting / server errors
						ctrlURL := origin + basePathPrefix + "*~0*" + suffix
						ctrlRR, cErr := r.client.Do(ctx, method, ctrlURL, nil, nil)
						if cErr != nil || ctrlRR.Response.StatusCode != statusNeg {
							// If *~0* doesn't match negative status, the setup is unstable
							continue
						}

						// FP Guard 2: Impossible non-existent filename prefix (e.g. ZZZNONEXIST99*~1*) MUST return statusNeg!
						// If the server returns statusPos for any random prefix, it is NOT parsing 8.3 names (e.g. SPA / custom 404 router).
						fakeURL1 := fmt.Sprintf("%s%sZZZNONEXIST99*~%d*%s", origin, basePathPrefix, tildeIdx, suffix)
						fakeRR1, fErr1 := r.client.Do(ctx, method, fakeURL1, nil, nil)
						if fErr1 != nil || fakeRR1.Response.StatusCode != statusNeg {
							continue
						}

						// FP Guard 3: Second impossible random prefix check
						fakeURL2 := fmt.Sprintf("%s%sQQQNOFILE88*~%d*%s", origin, basePathPrefix, tildeIdx, suffix)
						fakeRR2, fErr2 := r.client.Do(ctx, method, fakeURL2, nil, nil)
						if fErr2 != nil || fakeRR2.Response.StatusCode != statusNeg {
							continue
						}

						// FP Guard 4: Re-verify positive URL stability
						reVerifyRR, rErr := r.client.Do(ctx, method, posURL, nil, nil)
						if rErr != nil || reVerifyRR.Response.StatusCode != statusPos {
							continue
						}

						foundSetup = &workingSetup{
							basePath:    basePathPrefix,
							method:      method,
							suffix:      suffix,
							statusPos:   statusPos,
							statusNeg:   statusNeg,
							activeTilde: tildeIdx,
							posRR:       reVerifyRR,
							negRR:       negRR1,
							probeURL:    posURL,
						}
						break
					}
				}
				if foundSetup != nil {
					break
				}
			}
		}
	}

	// -------------------------------------------------------------------------
	// Stage 2 & 3: Shortname Discovery, Character Filter & Autocomplete Engine
	// -------------------------------------------------------------------------
	if foundSetup != nil {
		var discoveredShortnames []string
		var autocompletedFiles []string
		seenShortnames := map[string]struct{}{}

		// 2a. Common High-Yield Prefix Enumeration
		for _, prefix := range iisCommonPrefixes {
			if ctx.Err() != nil {
				break
			}
			enumURL := fmt.Sprintf("%s%s%s*~%d*%s", origin, foundSetup.basePath, prefix, foundSetup.activeTilde, foundSetup.suffix)
			enumRR, enumErr := r.client.Do(ctx, foundSetup.method, enumURL, nil, nil)
			if enumErr == nil && enumRR.Response.StatusCode == foundSetup.statusPos {
				// Verify candidate isn't a false match
				negCandidateURL := fmt.Sprintf("%s%s%sZZZ99*~%d*%s", origin, foundSetup.basePath, prefix, foundSetup.activeTilde, foundSetup.suffix)
				negCandidateRR, ncErr := r.client.Do(ctx, foundSetup.method, negCandidateURL, nil, nil)
				if ncErr == nil && negCandidateRR.Response.StatusCode == foundSetup.statusNeg {
					sname := fmt.Sprintf("%s*~%d*", prefix, foundSetup.activeTilde)
					if _, seen := seenShortnames[sname]; !seen {
						seenShortnames[sname] = struct{}{}
						discoveredShortnames = append(discoveredShortnames, sname)
					}
				}
			}
		}

		// 2b. Character Map Filter (Shortscan stage 2: probe existing characters)
		var activeChars strings.Builder
		for _, ch := range iisAlphanumChars {
			if ctx.Err() != nil {
				break
			}
			charURL := fmt.Sprintf("%s%s*%s*~%d*%s", origin, foundSetup.basePath, string(ch), foundSetup.activeTilde, foundSetup.suffix)
			charRR, cErr := r.client.Do(ctx, foundSetup.method, charURL, nil, nil)
			if cErr == nil && charRR.Response.StatusCode == foundSetup.statusPos {
				activeChars.WriteRune(ch)
			}
		}

		// 2c. Autocomplete Long Filenames via Wordlist & Method _ (IIS 405)
		for _, item := range iisWordlistEntries {
			if ctx.Err() != nil {
				break
			}
			// Test if 8.3 prefix of this wordlist item matches
			checkURL := fmt.Sprintf("%s%s%s%s", origin, foundSetup.basePath, item.short83, foundSetup.suffix)
			chkRR, chkErr := r.client.Do(ctx, foundSetup.method, checkURL, nil, nil)
			if chkErr == nil && chkRR.Response.StatusCode == foundSetup.statusPos {
				// Verify using IIS Method _ existence check (returns 405 Method Not Allowed when file exists)
				candidateURL := origin + foundSetup.basePath + item.full
				methodRR, mErr := r.client.Do(ctx, "_", candidateURL, nil, nil)
				if mErr == nil && (methodRR.Response.StatusCode == 405 || methodRR.Response.StatusCode == 200 || methodRR.Response.StatusCode == 403) {
					autocompletedFiles = append(autocompletedFiles, fmt.Sprintf("%s (%s)", item.full, item.short83))
				}
			}
		}

		signal := "iis_shortname"
		p := defaultPayload("iis_discovery", signal, foundSetup.probeURL, signal)
		f := r.verifyAndBuild(ctx, "iis_discovery", target, p, foundSetup.negRR, foundSetup.posRR, signal, false, false, "", "")
		if f != nil {
			f.Severity = "medium"
			f.Title = "Microsoft IIS 8.3 Short File Name (Tilde) Enumeration Vulnerability"
			desc := fmt.Sprintf("The web server running Microsoft IIS reveals the existence of short 8.3 file and directory names (working method: %s, suffix: %q, positive status: %d, negative status: %d).",
				foundSetup.method, foundSetup.suffix, foundSetup.statusPos, foundSetup.statusNeg)
			if len(discoveredShortnames) > 0 {
				desc += fmt.Sprintf(" Discovered 8.3 candidate shortnames: %s.", strings.Join(discoveredShortnames, ", "))
			}
			if len(autocompletedFiles) > 0 {
				desc += fmt.Sprintf(" Autocompleted full filenames: %s.", strings.Join(autocompletedFiles, ", "))
			}
			f.Description = desc
			r.recordFinding(ctx, &out, f, "iis_discovery", signal)
		}
	}

	baseline, _ := r.cachedEmptyProbe(ctx, target)

	// Check 2: IIS Extension Confusion & Source Disclosure (::$DATA / .( / .asp;.jpg)
	if strings.Contains(u.Path, ".asp") || strings.Contains(u.Path, ".aspx") || strings.Contains(u.Path, ".php") {
		dataURL := target.EndpointURL + "::$DATA"
		if r.scope.IsInScope(dataURL) {
			dRR, dErr := r.client.Do(ctx, "GET", dataURL, nil, nil)
			if dErr == nil && dRR.Response.StatusCode == 200 {
				body := dRR.Response.Body
				if strings.Contains(body, "<%@") || strings.Contains(body, "<script runat") || strings.Contains(body, "<?php") {
					signal := "iis_source_disclosure"
					p := defaultPayload("iis_discovery", signal, dataURL, signal)
					f := r.verifyAndBuild(ctx, "iis_discovery", target, p, baseline, dRR, signal, false, false, "", "")
					if f != nil {
						f.Severity = "critical"
						f.Title = "IIS NTFS Alternate Data Stream (::$DATA) Source Code Disclosure"
						f.Description = fmt.Sprintf("Source code of '%s' was disclosed by appending NTFS Alternate Data Stream identifier ::$DATA.", target.EndpointURL)
						r.recordFinding(ctx, &out, f, "iis_discovery", signal)
					}
				}
			}
		}
	}

	return out
}
