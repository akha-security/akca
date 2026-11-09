# Route authentication bypass false-positive review

Report: `akca-report-scan-97838cbf-1794034748161163300-cd7d80a5c5e8f69f.html`, finding 220, `x_original_url_header`.

The report compares an anonymous 403 on a path containing minified JavaScript with a 200 on `/` carrying that path in `X-Original-URL`. Its proof ledger contains baseline/probe/replay exchanges, but no authenticated resource reference or identity observation. This does not demonstrate access to the alleged protected resource. No requests to the live target were made during this review.

The module previously accepted keywords such as `dashboard`, or private-looking JSON, as sufficient resource identity evidence in anonymous scans. Failed negative/root controls did not consistently stop verification, and the recorded negative control reused the baseline instead of the actual nonexistent-route exchange.

Changes:

- Reject decoded JavaScript operators/function/export fragments at endpoint URL validation, before scanner requests.
- Require an authenticated request returning private content that matches the bypassed resource, or a configured private canary. Credentials must actually be present in the authenticated request.
- Fail closed when nonexistent-route or public-root controls are unavailable. Header overrides also need a nonexistent header-value control; a generic response to every header value is insufficient.
- Require the resource to reproduce anonymously three times, the canonical anonymous denial to remain stable, and the authenticated reference to remain stable. Private identities cannot be changed by volatile-field normalization.
- Enforce private-resource binding again in the central proof policy; status differences and repeated bodies alone are insufficient.
- Store actual control requests and the authenticated reference response in finding evidence. HTML reports show the reference and header controls in expandable evidence sections. Historical HTTP-only replays return inconclusive and require the original authorization verifier.

The HTML report is historical and has not been rewritten. A new scan is needed to apply the updated evidence requirements. Anonymous scans without a private reference/canary emit a missing-reference discovery event instead of confirming this vulnerability class.

Regression coverage includes public dashboard pages, private-looking anonymous JSON, ignored/indiscriminate proxy headers, unavailable controls, identity changes during replay, a disappearing private canary, transient canonical denial, and positive authenticated/canary proxy bypasses. Positive path-normalization detection is also retained.

Validation:

- `go test ./... -short -count=1 -timeout=120s` passed.
- `go vet ./...` passed before the additional HTML evidence presentation change.
- `go test ./internal/modules ./internal/verification ./internal/urlutil ./internal/app ./internal/report -count=1 -timeout=120s` passed after the final implementation changes, including the HTML evidence regression test.
- `go vet ./internal/modules ./internal/verification ./internal/urlutil ./internal/app ./internal/report` passed after the final implementation changes.
- Windows executable built with `go build -buildvcs=false -trimpath -ldflags='-s -w' -o ../akca-new.exe ./cmd/akca`; `--version` exited successfully. The workspace `akca.exe` was replaced with the verified build.
