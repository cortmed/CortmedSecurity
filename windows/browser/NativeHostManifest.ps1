# Cortmed tarayici koprusunun (native messaging host) bildirim dosyasini olusturur.
# Install.ps1 ve testler bu dosyayi nokta ile yukler; kendi basina hicbir sey calistirmaz.

# JSON metin degeri icin kacis: ters bolu, tirnak ve denetim karakterleri
function ConvertTo-JsonStringValue([string]$s) {
    $sb = New-Object Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        switch ($ch) {
            '\' { [void]$sb.Append('\\') }
            '"' { [void]$sb.Append('\"') }
            default {
                if ([int]$ch -lt 32) { [void]$sb.AppendFormat('\u{0:x4}', [int]$ch) } else { [void]$sb.Append($ch) }
            }
        }
    }
    return $sb.ToString()
}

# Sablondaki __HOST_PATH__ ve __EXTENSION_ID__ yerlerini doldurur; ciktisi gecerli JSON'dur.
function New-NativeHostManifestJson([string]$HostPath, [string]$ExtensionId, [string]$TemplatePath = (Join-Path $PSScriptRoot 'com.cortmed.security.json.template')) {
    if ($ExtensionId -cnotmatch '^[a-p]{32}$') { throw 'Eklenti kimliği geçersiz' }
    if (-not $HostPath) { throw 'Köprü yolu boş' }
    $tpl = [IO.File]::ReadAllText($TemplatePath, [Text.Encoding]::UTF8)
    $json = $tpl.Replace('__HOST_PATH__', (ConvertTo-JsonStringValue $HostPath)).Replace('__EXTENSION_ID__', $ExtensionId).Trim()
    # Uretilen metin gecerli bir JSON olmali; degilse yazmadan hata ver
    $null = $json | ConvertFrom-Json
    return $json
}
