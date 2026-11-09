# Target selection, scan order and WAF back-pressure

Implemented without rebuilding the application executable.

## Scan scheduling

Update (2026-11-08): the abbreviated crawl/hidden-name passes described below
caused avoidable coverage loss and have been replaced. The configured crawl
and configured hidden-name discovery now complete before priority modules;
visible URL hints prioritize handlers without excluding queryless application
pages. The follow-up pass remains for inputs discovered by later path fuzzing.
See `../2026-11-08/discovery-coverage-regression.md` for reproduction and fixes.
The following bullets describe the superseded 2026-11-07 implementation.

- Initial crawling is bounded to at most 32 page requests / 64 crawler requests, respecting smaller configured limits. Extended crawling follows priority checks and subtracts the initial crawler usage from configured crawler limits. Its initial usage is persisted for resume.
- Existing query, form, JSON and captured-body inputs are persisted before active discovery selection. Initial hidden-name guessing is bounded to 12 selected endpoint families, 8 candidates and 12 active probes per endpoint, with one discovery worker. Smaller configured limits remain in force.
- Captured-content analysis and input-specific SQLi/XSS/SSRF/authorization checks precede broad discovery. Initial passive analysis only consumes captured responses; missing content is handled in the later pass.
- Extended crawling, directory/path fuzzing and broad hidden-parameter discovery populate a fresh target snapshot. The follow-up pass processes newly discovered inputs. Only completed module/input work is skipped; completion is persisted for resume using hashed work identities.
- Path/proxy bypass checks run after the priority pass. Explicit session lifecycle checks remain last.

## Resource eligibility

The shared `targeting` package classifies static extensions, static directory trees, discovery documents, unavailable resources and recognizable WAF challenges before active input mutation. The guard is enforced both by module scheduling and direct SQLi/XSS entry points. Full-coverage settings do not bypass it.

Passive content analysis retains JS, CSS and directory responses. Observed dynamic reflection, captured native bodies and structured application responses can preserve active eligibility for unusual routes. An exact, repeatable `--force-active-url <url>` override is available for ambiguous resources; scope and unavailable-resource checks still apply. Classification is intentionally conservative and cannot establish that every unusual handler is static. Operators should review skip reasons and explicitly include unusual known input handlers.

Fuzzing now preserves the observed status, response headers and compact response body in discovery request templates. Asset paths do not enter the 403 bypass queue; recognized WAF challenge bodies do not become ordinary 403 candidates. Unknown application paths remain eligible for the existing bounded bypass verifier.

## WAF and traffic control

- WAF traffic recommendations now update actual request rates, session worker settings and HTTP transport admission limits. HTTP admission covers the response body lifetime and honors cancellation.
- Background discovery is deferred after host pressure instead of repeatedly issuing variants. Managed active scans defer after repeated blocking responses. Deferred targets produce incomplete coverage rather than a clean result.
- Recovery uses three GET responses from the first previously successful URL. Unrelated successful responses or ordinary 403 responses do not clear host pressure. Recovery is attempted once per pressure episode, with a bounded wait; other hosts can continue.
- Existing encoding/decoder-aware payload generation is preserved. Encoding does not imply that a WAF will allow a request.

## Validation

- All repository short tests passed: `go test ./... -short -count=1 -timeout=180s`.
- Full tests passed for app, modules, targeting, httpclient, params, reflection, fuzzing, bypass403, storage, crawler and CLI after the final implementation changes.
- `go vet ./...` and `git diff --check` passed.
- Added integration coverage verifies that a newly discovered parameter reaches the XSS module during follow-up and that completed input work is not repeated after restoring a checkpoint.
- Added tests verify zero SQLi/XSS/SSRF requests against static/code-derived targets, eligibility of dynamic/native inputs and exact overrides, response-lifetime concurrency limits, and known-URL WAF recovery.
- No requests to live third-party targets were made. No application EXE build was performed.

Remaining tradeoffs: the expanded crawler can revisit seed pages within its remaining budget; classification may require explicit overrides for unconventional dynamic resources; WAF deferral can leave coverage incomplete. These are visible limits, not evidence that an untested target is safe.
