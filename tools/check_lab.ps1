param(
  [string]$exe    = ".\target\release\cli.exe",
  [string]$pcap   = "data\dns-lab-10q.pcapng",
  [string]$config = "config\demo.toml"
)

$ErrorActionPreference = "Stop"

# Temiz başla
Remove-Item -Force target\alerts.ndjson -ErrorAction SilentlyContinue

# Çalıştır
& $exe --mode batch --pcap $pcap --config $config --out target\alerts.ndjson

# Oku
$alerts = Get-Content target\alerts.ndjson | % { $_ | ConvertFrom-Json }
if (-not $alerts) { throw "ALERT YOK (beklenen: demo.invalid)" }

# demo.invalid dışı varsa FAIL
$fp = $alerts | ? { $_.root -ne "demo.invalid" }
if ($fp) {
  $roots = ($fp | Select-Object -ExpandProperty root | Sort-Object -Unique) -join ", "
  throw "FALSE POSITIVE: $roots"
}

"OK - yalnızca demo.invalid alarm verdi."
