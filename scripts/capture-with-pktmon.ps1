# requires: admin
# pipeline: pktmon capture -> etl -> pcapng -> cargo analyze -> assert-5v5
Param(
  [string]$DnsServer = "1.1.1.1",
  [string]$Config    = "config\demo.toml"
)

function Ensure-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Bu betik yönetici olarak çalıştırılmalı (Run as Administrator)."
  }
}
function Safe-Run($cmd, $args) {
  Write-Host ">> $cmd $args"
  & $cmd $args
  if ($LASTEXITCODE -ne 0) { throw "Komut hata ile döndü: $cmd $args" }
}

Ensure-Admin
Push-Location (Split-Path -Parent $PSCommandPath)  # scripts/
Set-Location ..

New-Item -ItemType Directory -Path data   -Force | Out-Null
New-Item -ItemType Directory -Path target -Force | Out-Null

try { Safe-Run pktmon "filter remove" } catch { }
Safe-Run pktmon "filter add -t UDP -p 53"

$etl = "PktMon.etl"
if (Test-Path $etl) { Remove-Item $etl -Force }

Safe-Run pktmon "start"

Write-Host "`n== TRAFİK ÜRETİLİYOR ==" -ForegroundColor Yellow
$gen = ".\scripts\make-5patterns.ps1"
if (Test-Path $gen) {
  & powershell -ExecutionPolicy Bypass -File $gen
} else {
  Write-Warning "make-5patterns.ps1 bulunamadı, bu adımı atlıyorum."
}

Start-Sleep -Seconds 3
Safe-Run pktmon "stop"

$ts   = Get-Date -Format "yyyyMMdd-HHmmss"
$pcap = ".\data\live-$ts.pcapng"

$converted = $false
try {
  Safe-Run pktmon "pcapng $etl -o $pcap"
  $converted = $true
} catch {
  Write-Warning "pktmon pcapng desteklenmiyor olabilir, etl2pcap denenecek."
}
if (-not $converted) {
  Safe-Run pktmon "etl2pcap $etl -o $pcap"
}

if (!(Test-Path $pcap)) { throw "PCAPNG üretilmedi: $pcap" }
Write-Host "`nPCAP yazıldı: $pcap" -ForegroundColor Cyan

Write-Host "`n== ANALİZ BAŞLIYOR ==" -ForegroundColor Green
Safe-Run cargo "run --bin cli -- --mode batch --pcap `"$pcap`" --config `"$Config`" --out `"target\alerts.ndjson`""

Write-Host "`n== ASSERT-5v5 ÇALIŞIYOR ==" -ForegroundColor Green
Safe-Run powershell "-ExecutionPolicy Bypass -File .\scripts\assert-5v5.ps1"

Pop-Location
