# windows/cortmed-logo.png dosyasindan eklenti simgeleri (16, 48, 128 piksel PNG) uretir.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$src = Join-Path $root 'windows\cortmed-logo.png'
$outDir = Join-Path $root 'browser\extension\icons'
New-Item -ItemType Directory -Force $outDir | Out-Null

$img = [Drawing.Image]::FromFile($src)
try {
    foreach ($size in 16, 48, 128) {
        $bmp = New-Object Drawing.Bitmap($size, $size, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
        try {
            $g = [Drawing.Graphics]::FromImage($bmp)
            try {
                $g.Clear([Drawing.Color]::Transparent)
                $g.CompositingQuality = [Drawing.Drawing2D.CompositingQuality]::HighQuality
                $g.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
                $g.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::HighQuality
                $g.PixelOffsetMode = [Drawing.Drawing2D.PixelOffsetMode]::HighQuality
                $attr = New-Object Drawing.Imaging.ImageAttributes
                $attr.SetWrapMode([Drawing.Drawing2D.WrapMode]::TileFlipXY)
                $g.DrawImage($img, (New-Object Drawing.Rectangle(0, 0, $size, $size)), 0, 0, $img.Width, $img.Height, [Drawing.GraphicsUnit]::Pixel, $attr)
                $attr.Dispose()
            } finally { $g.Dispose() }
            $dst = Join-Path $outDir "$size.png"
            $bmp.Save($dst, [Drawing.Imaging.ImageFormat]::Png)
            Write-Host "Yazildi: $dst"
        } finally { $bmp.Dispose() }
    }
} finally { $img.Dispose() }
