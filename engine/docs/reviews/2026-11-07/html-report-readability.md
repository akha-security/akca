# HTML report readability

Changes apply to newly generated reports; historical HTML files and the application EXE were not modified.

- Constrain flex/grid children and wrap unbroken URLs, payloads, metadata and table cells. Large tables use a bounded horizontal scroll region on narrow screens; HTTP blocks and payloads have bounded vertical views.
- Show response evidence first, in compact mode, with existing expand/copy controls retained. Print styles continue to expose stored content.
- Remove repeated endpoint metadata when it matches the finding heading. Preserve a distinct probe URL, such as a proxy bypass request to a different route.
- Omit empty API-key sections and zero-count evidence categories. Move generic verification text, routine diagnostics, path discovery and crawler traffic into expandable sections. Execution errors and explicit coverage gaps remain visible.
- Use neutral no-finding/inconclusive labels instead of claiming that a target is safe; informational records retain their own label.
- Preserve UTF-8 boundaries during evidence compaction. Preserve small windows around exact evidence markers when a large response's head/tail excerpt would omit them.
- Highlight matches against the original escaped text rather than reprocessing generated span tags. Overlapping markers no longer corrupt the HTML markup.

Validation: full report and evidence-marker tests passed, including clipboard/tab/expand JavaScript tests, Unicode compaction, middle-of-response evidence and diagnostic visibility checks. App/CLI short tests, relevant `go vet` checks and `git diff --check` also passed.

## Professional light report redesign

Following the requested light, professional appearance, the report now uses one restrained light palette, a compact brand header, a plain navigation row, four summary values and small severity counts. The threat gauge, severity circles, theme toggle and oversized decorative elements were removed. CSS is embedded from `internal/report/professional.css`; exported HTML remains self-contained and offline.

Findings appear immediately after the overview. Each card presents the title, severity, confidence, endpoint, description, impact and remediation. Technical metadata and HTTP evidence are grouped in a closed disclosure; full long endpoint URLs remain accessible. Scope, detailed metrics and root-cause groups are also disclosures. Coverage failures remain visible. Category filters can be deselected by clicking again, and All resets both category and severity. The default summary no longer labels every report as submission-ready.

When `AKCA_REPORT_PREVIEW_DIR` is set, `TestProfessionalReportPreview` writes a realistic three-finding sample to `report-preview.html` and a mobile frame to `report-preview-mobile.html`. `TestHTMLReportStressPreview` separately writes extreme-content fixtures to `report-stress.html` and `report-stress-mobile.html`. Both use invented data and never contact a scan target.

Validation includes all report templates, evidence-marker checks, clipboard/evidence controls, combined category/severity reset behavior, `go vet` and whitespace checks. Interactive visual verification was unavailable: Browser Use rejected local `file://` navigation because its URL policy allows only HTTP/HTTPS. No alternate browser surface or workaround was used; browser rendering and print output have not been visually verified.

## v0.3.1 visual update — 9 November 2026

The report now opens with a centered 148-pixel AKCA logo, the full product name below it, a clear target/date row, and larger type throughout the overview, findings and HTTP evidence. The four summary values use separate cards. The 375-pixel sample report and a 360-pixel content viewport with long URLs were rendered in local headless Chrome; the stress report measured zero horizontal overflow. The report package tests passed after the redesign. Historical exported HTML files are unchanged; new exports use the updated template.
