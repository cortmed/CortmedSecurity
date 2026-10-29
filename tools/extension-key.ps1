# Cortmed tarayici eklentisi anahtari.
# RSA-2048 uretir, acik anahtarin SPKI DER halini base64 olarak manifest.json "key" alanina yazar,
# eklenti kimligini hesaplar (SHA-256(DER) ilk 32 hex, 0-f -> a-p) ve browser/extension-id.txt'ye yazar.
# Ozel anahtar (PKCS#1 PEM) android/keystore/cortmed-extension.pem dosyasina gider; bu klasor gitignore'dadir.
# Anahtar zaten varsa yeniden uretmez (kimlik degisirse yerel kopru reddeder); -Force ile zorlanir.
param([switch]$Force)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$manifestPath = Join-Path $root 'browser\extension\manifest.json'
$idPath = Join-Path $root 'browser\extension-id.txt'
$pemDir = Join-Path $root 'android\keystore'
$pemPath = Join-Path $pemDir 'cortmed-extension.pem'

# --- DER yardimcilari ---
function Get-DerLength([int]$n) {
    if ($n -lt 0x80) { return [byte[]]@($n) }
    $b = New-Object System.Collections.Generic.List[byte]
    while ($n -gt 0) { $b.Insert(0, [byte]($n -band 0xFF)); $n = $n -shr 8 }
    return [byte[]](@([byte](0x80 -bor $b.Count)) + $b.ToArray())
}
function New-Der([byte]$tag, [byte[]]$content) {
    if ($null -eq $content) { $content = [byte[]]@() }
    return [byte[]](@($tag) + (Get-DerLength $content.Length) + $content)
}
function New-DerInteger([byte[]]$bigEndianUnsigned) {
    $i = 0
    while ($i -lt $bigEndianUnsigned.Length - 1 -and $bigEndianUnsigned[$i] -eq 0) { $i++ }
    $v = [byte[]]$bigEndianUnsigned[$i..($bigEndianUnsigned.Length - 1)]
    if ($v[0] -band 0x80) { $v = [byte[]](@([byte]0) + $v) }
    return New-Der 0x02 $v
}
function New-DerSequence([byte[][]]$parts) {
    $all = New-Object System.Collections.Generic.List[byte]
    foreach ($p in $parts) { $all.AddRange($p) }
    return New-Der 0x30 $all.ToArray()
}

function ConvertTo-SpkiDer($p) {
    $rsaPub = New-DerSequence @((New-DerInteger $p.Modulus), (New-DerInteger $p.Exponent))
    # AlgorithmIdentifier: rsaEncryption 1.2.840.113549.1.1.1 + NULL
    $oid = [byte[]](0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01)
    $null5 = [byte[]](0x05, 0x00)
    $algId = New-DerSequence @($oid, $null5)
    $bitString = New-Der 0x03 ([byte[]](@([byte]0) + $rsaPub))
    return New-DerSequence @($algId, $bitString)
}

function ConvertTo-Pkcs1Der($p) {
    return New-DerSequence @(
        (New-DerInteger ([byte[]]@(0))),
        (New-DerInteger $p.Modulus), (New-DerInteger $p.Exponent), (New-DerInteger $p.D),
        (New-DerInteger $p.P), (New-DerInteger $p.Q), (New-DerInteger $p.DP), (New-DerInteger $p.DQ),
        (New-DerInteger $p.InverseQ))
}

function Get-ExtensionId([byte[]]$der) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash($der) } finally { $sha.Dispose() }
    $sb = New-Object Text.StringBuilder
    for ($i = 0; $i -lt 16; $i++) {
        [void]$sb.Append([char](97 + ($h[$i] -shr 4)))
        [void]$sb.Append([char](97 + ($h[$i] -band 15)))
    }
    return $sb.ToString()
}

$utf8 = New-Object Text.UTF8Encoding($false)
$manifest = [IO.File]::ReadAllText($manifestPath, $utf8)
$keyRx = '"key"\s*:\s*"([^"]*)"'
$m = [regex]::Match($manifest, $keyRx)
if (-not $m.Success) { throw 'manifest.json icinde "key" alani yok' }
if ($m.Groups[1].Value -and -not $Force) {
    $der = [Convert]::FromBase64String($m.Groups[1].Value)
    $id = Get-ExtensionId $der
    [IO.File]::WriteAllText($idPath, $id, $utf8)
    Write-Host "Anahtar zaten var (yeniden uretmek icin -Force). Eklenti kimligi: $id"
    exit 0
}

$rsa = New-Object Security.Cryptography.RSACryptoServiceProvider(2048)
try {
    $rsa.PersistKeyInCsp = $false
    $params = $rsa.ExportParameters($true)
} finally { $rsa.Dispose() }

$spki = ConvertTo-SpkiDer $params
$pkcs1 = ConvertTo-Pkcs1Der $params
$b64 = [Convert]::ToBase64String($spki)
$id = Get-ExtensionId $spki

# Ozel anahtar: once yazilir, sonra manifest guncellenir
New-Item -ItemType Directory -Force $pemDir | Out-Null
$flat = [Convert]::ToBase64String($pkcs1)
$lines = for ($i = 0; $i -lt $flat.Length; $i += 64) { $flat.Substring($i, [Math]::Min(64, $flat.Length - $i)) }
$pem = "-----BEGIN RSA PRIVATE KEY-----`n" + ($lines -join "`n") + "`n-----END RSA PRIVATE KEY-----`n"
[IO.File]::WriteAllText($pemPath, $pem, $utf8)
# Yalnizca gecerli kullanici okuyabilsin
& icacls $pemPath /inheritance:r /grant:r "$($env:USERNAME):F" | Out-Null

$manifest = [regex]::Replace($manifest, $keyRx, ('"key": "' + $b64 + '"'), 1)
[IO.File]::WriteAllText($manifestPath, $manifest, $utf8)
[IO.File]::WriteAllText($idPath, $id, $utf8)

Write-Host "Eklenti kimligi: $id"
Write-Host "Ozel anahtar: $pemPath (depoya EKLEMEYIN)"
