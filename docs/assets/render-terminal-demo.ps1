# Render the actual ANSI capture from TestReadmeCapture in a Kali-style terminal.
# No finding text is authored or modified here.
Add-Type -AssemblyName System.Drawing
$raw = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'terminal-capture.ansi'))
$lines = $raw.Trim().Split([char]10)
$cell = 15
$lineHeight = 30
$width = 1320
$height = 180 + $lines.Count * $lineHeight
$bitmap = [Drawing.Bitmap]::new($width, $height)
$g = [Drawing.Graphics]::FromImage($bitmap)
$g.TextRenderingHint = [Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$font = [Drawing.Font]::new('Consolas', 24, [Drawing.FontStyle]::Regular, [Drawing.GraphicsUnit]::Pixel)
$small = [Drawing.Font]::new('Consolas', 19, [Drawing.FontStyle]::Regular, [Drawing.GraphicsUnit]::Pixel)
$format = [Drawing.StringFormat]::GenericTypographic.Clone()
function DrawText($text, $x, $y, $color, $face = $font) {
    $brush = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml($color))
    $g.DrawString($text, $face, $brush, $x, $y, $format)
    $brush.Dispose()
}
$colors = @{75='#5fafff';78='#5fd787';221='#ffdf5f';203='#ff5f5f';81='#5fd7ff';209='#ff875f';252='#d0d0d0';245='#8a8a8a';239='#4e4e4e';255='#eeeeee';141='#af87ff'}
try {
    $g.Clear([Drawing.ColorTranslator]::FromHtml('#171717'))
    $bar = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#272727'))
    $g.FillRectangle($bar, 0, 0, $width, 47)
    $bar.Dispose()
    DrawText 'akca@kali: ~/akca/engine' 28 12 '#c8c8c8' $small
    DrawText 'LOCAL LAB / CAPTURED AKCA OUTPUT' 902 12 '#8a8a8a' $small
    DrawText '┌──(akca㉿kali)-[~/akca/engine]' 28 66 '#5fafff'
    DrawText '└─$ go test ./cmd/akca -run TestReadmeCapture -v' 28 97 '#d0d0d0'
    $row=0
    foreach ($line in $lines) {
        $col=0
        $color='#d0d0d0'
        foreach ($part in [regex]::Split($line.TrimEnd([char]13), '(\x1b\[[0-9;]*m)')) {
            if ($part -match '^\x1b\[([0-9;]*)m$') {
                $code=$Matches[1]
                if ($code -eq '0') { $color='#d0d0d0' }
                if ($code -match '38;5;(\d+)') {
                    $n=[int]$Matches[1]
                    if ($colors.ContainsKey($n)) { $color=$colors[$n] }
                }
                continue
            }
            foreach ($ch in $part.ToCharArray()) {
                DrawText ([string]$ch) (28 + $col*$cell) (152 + $row*$lineHeight) $color
                $col++
            }
        }
        $row++
    }
    $bitmap.Save((Join-Path $PSScriptRoot 'terminal-demo.png'), [Drawing.Imaging.ImageFormat]::Png)
} finally {
    $format.Dispose(); $font.Dispose(); $small.Dispose(); $g.Dispose(); $bitmap.Dispose()
}
