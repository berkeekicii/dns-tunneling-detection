param(
  [string]$exe            = ".\target\release\cli.exe",
  [string]$pcap           = "data\dns-lab-10q.pcapng",
  [string]$config         = "config\demo.toml",
  [int]   $threshold_secs = 60
)

$ErrorActionPreference = "Stop"
$alerts = "target\alerts.ndjson"

# Temiz başlangıç
Remove-Item -Force $alerts -ErrorAction SilentlyContinue

# CLI'yi arka planda başlat
$start = Get-Date
$proc = Start-Process $exe -ArgumentList @(
  "--mode","batch",
  "--pcap",$pcap,
  "--config",$config,
  "--out",$alerts
) -PassThru -WindowStyle Hidden

# İlk alarmı bekle ve gecikmeyi ölç
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$firstAlertAt = $null

while ($sw.Elapsed.TotalSeconds -lt ($threshold_secs * 3)) {
  if (Test-Path $alerts) {
    # Dosya dolmaya başlamış mı? (en az 1 satır)
    $line = Get-Content $alerts -TotalCount 1 -ErrorAction SilentlyContinue
    if ($line) { $firstAlertAt = Get-Date; break }
  }
  if ($proc.HasExited -and -not (Test-Path $alerts)) { break }
  Start-Sleep -Milliseconds 150
}
$sw.Stop()

# Süreyi hesapla
$latency = if ($firstAlertAt) {
  [int][Math]::Round( ($firstAlertAt - $start).TotalSeconds )
} else {
  [int][Math]::Round( $sw.Elapsed.TotalSeconds )
}

# Süreç bitti mi?
try { $proc | Wait-Process -Timeout 5 } catch {}

# Sonuçları değerlendir
if (-not (Test-Path $alerts)) {
  Write-Host "FAIL  alerts.ndjson oluşmadı." -ForegroundColor Red
  exit 1
}

$cnt = (Get-Content $alerts | Where-Object { $_.Trim() -ne "" }).Count
Write-Host ("latency={0}s alerts={1}" -f $latency, $cnt)

if ($cnt -lt 1) {
  Write-Host "FAIL  hiç alarm yok." -ForegroundColor Red
  exit 1
}

if ($latency -le $threshold_secs) {
  Write-Host ("PASS  ilk alarm {0}s (<= {1}s)" -f $latency, $threshold_secs) -ForegroundColor Green
  exit 0
} else {
  Write-Host ("FAIL  ilk alarm {0}s (> {1}s)" -f $latency, $threshold_secs) -ForegroundColor Red
  exit 1
}
