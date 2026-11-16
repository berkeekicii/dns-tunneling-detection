# tools/render_incidents.ps1
# Girdi  : target/alerts.ndjson
# Çıktı  : target/incidents.ndjson (NDJSON: her satır tek JSON)

$alertsPath = "target\alerts.ndjson"
$outPath    = "target\incidents.ndjson"

# Model / sürüm bilgileri
$modelFile  = "models\iforest.onnx"
$modelHash  = (Get-FileHash $modelFile -Algorithm SHA256).Hash

# build_id: exe ProductVersion -> yoksa git SHA -> yoksa exe SHA-256 kısa
$buildId = (Get-Item ".\target\release\cli.exe").VersionInfo.ProductVersion
if (-not $buildId) {
  try   { $buildId = (git rev-parse --short HEAD) } 
  catch { $buildId = (Get-FileHash ".\target\release\cli.exe" -Algorithm SHA256).Hash.Substring(0,12) }
}

# ONNX Runtime sürümü (DLL dosya sürümü)
$ortVersion = (Get-Item ".\target\release\onnxruntime.dll").VersionInfo.FileVersion

# IP maskeleme (IPv4: son oktet -> x, IPv6: ilk 4 blok -> ::x)
function Mask-IP([string]$ip) {
  if (-not $ip) { return $null }
  if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') {
    return ($ip -replace '(\d+\.\d+\.\d+)\.\d+', '$1.x')
  } elseif ($ip -like '*:*') {
    return ($ip -replace '^((?:[0-9A-Fa-f]{1,4}:){4}).*$', '$1::x')
  } else { return $ip }
}

# Oku -> dönüştür -> yaz
Remove-Item -Force $outPath -ErrorAction SilentlyContinue
Get-Content $alertsPath | ForEach-Object {
  if (-not $_) { return } # boş satır atla (NDJSON kuralı)

  $a = $_ | ConvertFrom-Json

  $obj = [pscustomobject]@{
    ts            = [int64]$a.ts
    qname         = $a.qname
    qtype         = $a.qtype
    root          = $a.root
    reasons       = $a.reasons
    ml_score      = $a.ml_score
    rule_score    = $(if ($a.PSObject.Properties.Name -contains 'score') { $a.score } else { $null })

    # CLI tarafı src_ip/dst_ip yazmıyorsa null kalır (ileride ekleyeceğiz)
    src_ip_masked = $(if ($a.PSObject.Properties.Name -contains 'src_ip') { Mask-IP $a.src_ip } else { $null })
    dst_ip_masked = $(if ($a.PSObject.Properties.Name -contains 'dst_ip') { Mask-IP $a.dst_ip } else { $null })

    model_sha256  = $modelHash
    build_id      = $buildId
    ort_version   = $ortVersion
  }

  $line = $obj | ConvertTo-Json -Compress
  Add-Content -Path $outPath -Value $line
}

"OK: wrote $outPath"
