# Discovery coverage and inconclusive PHP2Shell assessments

## Confirmed problems

- The bootstrap hidden-name policy lowered the normal configured endpoint,
  candidate and probe budgets to 12 endpoints, 8 names and 12 probes. Names
  found later were unavailable to the priority module pass until path fuzzing
  and extended discovery completed.
- `likelyParameterEndpoint` was an eligibility gate. Queryless PHP and normal
  HTML handlers could be omitted even though hidden parameters exist precisely
  where no visible query name is available.
- An additional per-surface cap silently reduced the configured candidate list
  to 16, 40 or 48 names.
- PHP2Shell's normal full-scan path is a passive metadata assessment. A usable
  HTTP response with no PHP version was classified as a completed module target
  and the CLI could display a green completion plus a no-vulnerabilities message.
  This did not establish absence of PHP2Shell exposure.
- PHP target selection preferred an empty or failing index response over root
  metadata containing actual PHP version evidence.
- On this machine `Get-Command akca` resolves to
  `C:\Users\caner\go\bin\akca.exe`, dated 2026-10-23, not the workspace executable
  built on 2026-11-07. The installed copy reported an unknown build identity and
  had a different SHA-256. This is separate from the source regressions.

## Changes

- Complete the configured crawl and hidden-name discovery before priority
  modules. Remove the artificial initial caps and the redundant late crawl.
- Use visible input hints to prioritize, without excluding otherwise eligible
  queryless handlers. Preserve family deduplication, finite configured budgets,
  calibrated batching, confirmation checks, static-resource rejection and
  unavailable-resource rejection.
- Honor the configured candidate-name limit rather than silently narrowing it
  by response type or path. Keep method-matched JSON/form/body discovery.
- Treat unknown or blocked PHP2Shell exposure as inconclusive. Emit a coverage
  event and show INCONCLUSIVE instead of a green COMPLETED phase. Incomplete
  scan summaries no longer say no vulnerabilities were detected.
- Prefer actual observed PHP version evidence over an uninformative index.
  Normalize origin-level PHP work before completion filtering so an unknown
  assessment is not repeated as a misleading successful follow-up check.
- Normal full CLI scans now run the existing bounded PHP2Shell active check
  automatically after broad vulnerability and exposure modules. It is limited
  to one root/index endpoint per explicitly configured origin, serial across
  origins, and does not follow redirects. Passive and narrow module modes do
  not inherit it. The active signal remains a candidate memory-exhaustion
  finding, not proof of remote code execution.
- When the memory-error signature is observed, finding evidence now cites the
  actual POST request and response. Its large multipart request body is
  replaced in persisted evidence by a size note.
- Reused passive response-cache hits now count as module evidence. Modules
  whose targets were all skipped report SKIPPED/BLOCKED instead of a green
  COMPLETED phase. Core injection checks precede broad authentication/path
  checks, and the PHP2Shell memory-pressure test runs near the end.

## Validation

The new hidden-input regression failed on the previous implementation for both
`/index.php` and `/search`. After the fix, hidden `page` and `language` inputs
reach the initial vulnerability target list. A separate regression checks that
40 linked application pages are actually fetched before module scanning, rather
than being constrained to the former 32-page bootstrap.

Focused checks also cover native GET/POST/JSON discovery, unknown PHP exposure,
known PHP version metadata, automatic full-scan memory-signature detection and
its POST evidence, PHP version evidence selection, completed-work filtering,
cache-hit coverage accounting, static-only skipped modules, scan ordering and
interactive/noninteractive CLI status. All fixtures use local servers or an
in-process fake transport; no request was sent to the user's domain or another
external scan target.

Validation completed: `go test ./... -short -count=1 -timeout=180s`,
`go vet ./...` and `git diff --check` passed. A successful test fixture is not
verification of the user's deployed target, which was not contacted.

## Delivered executable

Built Windows amd64 with CGO disabled, trimpath and stripped symbols. The build
identity contains commit `421a74ad49af` plus a dirty-worktree marker; build date
is `2026-11-08T11:30:09Z`. The staged and workspace executables have SHA-256
`030058900EA64A391B62D3ACB4C91867CFFC39DB3F3579E7E512A69D93CA2BCE`.
Version and help smoke checks passed. The prior workspace and PATH binaries
were `332B4DB4BC80FAB48E87F7AA5432F297D66958E11C135343329C01BF46F43968`.
The workspace executable was updated. Windows refused to overwrite the PATH
copy because the file is in use; that copy remains unchanged and must be
replaced after its holder exits. A separately named build is available as
`C:\Users\caner\go\bin\akca-php2shell-active.exe`. The currently running scan
was left untouched.

## Later report correction

The stopped scan `scan-fefbfdc9-1794130071560637000-90b31f00c3fd0747`
stored two SQLi leads with `Potential` and `NeedsManualReview` confidence.
The interrupt report's fast path omitted all manual leads, leaving the CLI
cards absent from HTML. Fast partial internal reports now retain a bounded
manual lead section and link to it from the report navigation. CLI cards for
these confidence levels say `UNVERIFIED LEAD`. The report rebuilt from the
stopped scan contains both records in that section; neither is presented as
confirmed SQL injection.

`Upgrade-Insecure-Requests` and similar browser control headers are now
excluded from active injection targets. The source change was checked with
affected-package tests, `go vet` on those packages and `git diff --check`.
The new build (`2026-11-08T12:08:27Z`, SHA-256
`64ED98928E7EA2F99BE5A521F2D193F082A70D040462DAFCE778DF52B8C7FAA5`)
was installed to both workspace `akca.exe` and the resolved PATH executable
`C:\Users\caner\go\bin\akca.exe` after the old scan stopped.
