# Terminal capture

The README image contains actual XSS and SQL injection events from the local
integration lab. The production ConsoleWriter formats each finding. Neither
finding text nor confidence labels are supplied by the image renderer.

The integration run sent 258 requests through the lab transport. The quick
subset produced XSS and SQL injection findings; no SSTI finding is fabricated
to fill the image. Loopback ports and response timing vary on each run.

The title bar and shell prompt provide a Kali-style theme. This is a rendering
of captured ANSI output, not an operating-system screenshot or a full CLI scan.
The lab helper uses its integration subset. It does not demonstrate all
production scan phases.

From the repository root on Windows PowerShell:

```powershell
$env:AKCA_README_CAPTURE = Join-Path (Get-Location).Path 'docs/assets/terminal-capture.ansi'
Push-Location engine
go test ./cmd/akca -run '^TestReadmeCapture$' -count=1 -v
Pop-Location
Remove-Item Env:AKCA_README_CAPTURE
./docs/assets/render-terminal-demo.ps1
```

The capture test skips unless AKCA_README_CAPTURE is set. It creates a local lab
and temporary database, selects the first finding for each requested injection
class, and writes the console output verbatim. The PowerShell renderer reads
that capture and maps ANSI colors onto a fixed terminal character grid.
