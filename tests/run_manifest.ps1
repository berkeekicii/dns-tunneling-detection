param(
  [string]$manifest = $null,
  [string]$mode     = 'cargo',   # 'cargo' | 'exe'
  [string]$exe      = ".\target\release\cli.exe"  # mode='exe' ise kullanılır
)

$ErrorActionPreference = 'Stop'

# Betik kökü ve repo kökü
$scriptRoot = $PSScriptRoot; if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot   = Split-Path $scriptRoot -Parent
Set-Location $repoRoot

# Varsayılan manifest yolu
if (-not $manifest) { $manifest = Join-Path $scriptRoot 'manifest.ndjson' }
if (-not (Test-Path $manifest)) { throw "Manifest bulunamadı: $manifest" }

# Yardımcı: HTML -> PDF (Edge headless ile)
function Convert-HtmlToPdf([string]$html, [string]$pdf){
  try {
    # Tarayıcıyı sırayla dene: Edge -> Chrome
    $edgePath1 = "$Env:ProgramFiles(x86)\Microsoft\Edge\Application\msedge.exe"
    $edgePath2 = "$Env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
    $chromePath1 = "$Env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe"
    $chromePath2 = "$Env:ProgramFiles\Google\Chrome\Application\chrome.exe"

    $browser = $null
    $cmd = Get-Command msedge -ErrorAction SilentlyContinue
    if ($cmd) { $browser = $cmd.Path }
    elseif (Test-Path $edgePath1) { $browser = $edgePath1 }
    elseif (Test-Path $edgePath2) { $browser = $edgePath2 }
    else {
      $cmd = Get-Command chrome -ErrorAction SilentlyContinue
      if ($cmd) { $browser = $cmd.Path }
      elseif (Test-Path $chromePath1) { $browser = $chromePath1 }
      elseif (Test-Path $chromePath2) { $browser = $chromePath2 }
    }

    if (-not $browser) {
      Write-Host "[pdf] Uygun tarayıcı bulunamadı, PDF üretilmedi (HTML mevcut)." -ForegroundColor DarkYellow
      return $false
    }

    $args = @('--headless','--disable-gpu','--no-sandbox',"--print-to-pdf=$pdf", $html)
    & $browser @args | Out-Null
    if (Test-Path $pdf) {
      Write-Host "[pdf] OK - $pdf" -ForegroundColor Green
      return $true
    } else {
      Write-Host "[pdf] Üretilemedi (komut döndü ama dosya yok)." -ForegroundColor DarkYellow
      return $false
    }
  } catch {
    Write-Host "[pdf] Hata: $($_.Exception.Message)" -ForegroundColor Red
    return $false
  }
}

# Çıktılar için kök
$outRoot = Join-Path $repoRoot 'target\manifest'
New-Item -ItemType Directory -Force -Path $outRoot | Out-Null

# Manifest satırlarını oku (NDJSON)
$jobs = Get-Content $manifest | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_ | ConvertFrom-Json }
if (-not $jobs -or $jobs.Count -eq 0) { throw "Manifest boş: $manifest" }

$summary = @()

foreach($job in $jobs){
  $name   = $job.name
  $pcap   = $job.pcap
  $config = $job.config
  $label  = $job.label  # 'good' | 'bad' gibi

  if (-not $name)   { throw "Satırda 'name' yok: $($job | ConvertTo-Json -Compress)" }
  if (-not $pcap)   { throw "Satırda 'pcap' yok: $name" }
  if (-not $config) { throw "Satırda 'config' yok: $name" }

  $pcapPath   = Resolve-Path $pcap
  $configPath = Resolve-Path $config
  $caseOut    = Join-Path $outRoot $name
  New-Item -ItemType Directory -Force -Path $caseOut | Out-Null

  $alerts = Join-Path $caseOut 'alerts.ndjson'
  if (Test-Path $alerts) { Remove-Item -Force $alerts }

  Write-Host "==> Çalıştırılıyor: $name (pcap=$pcapPath, config=$configPath)" -ForegroundColor Cyan

  if ($mode -eq 'exe') {
    if (-not (Test-Path $exe)) { throw "exe bulunamadı: $exe (mode=exe)" }
    & $exe --mode batch --pcap $pcapPath --config $configPath --out $alerts
  } else {
    # cargo run (release değil; hızlı derleme için debug). İstersen --release ekleyebilirsin.
    cargo run --bin cli -- --mode batch --pcap $pcapPath --config $configPath --out $alerts
  }

  if (-not (Test-Path $alerts)) { throw "Alert dosyası oluşmadı: $alerts" }

  # Kısa metrik
  $cnt = (Get-Content $alerts | Where-Object { $_.Trim() -ne '' }).Count
  Write-Host ("    alerts={0}" -f $cnt)

  # HTML rapor
  $html = Join-Path $caseOut 'report.html'
  try {
    & (Join-Path $repoRoot 'tools\report_html.ps1') -alerts $alerts -out $html | Out-Null
  } catch {
    Write-Host "[html] Hata: $($_.Exception.Message)" -ForegroundColor Red
  }
  $htmlOk = Test-Path $html

  # PDF rapor (Edge varsa)
  $pdf  = Join-Path $caseOut 'report.pdf'
  $pdfOk = $false
  if ($htmlOk) { $pdfOk = Convert-HtmlToPdf -html $html -pdf $pdf }

  $summary += [pscustomobject]@{
    name   = $name
    label  = $label
    alerts = $cnt
    html   = if ($htmlOk) { (Resolve-Path $html).Path } else { $null }
    pdf    = if ($pdfOk)  { (Resolve-Path $pdf).Path }  else { $null }
  }
}

Write-Host "`n=== ÖZET ===" -ForegroundColor Yellow
$summary | Format-Table name, label, alerts, html, pdf

Write-Host "`nNot: 'good' için 0-çok az, 'bad' için >=1 alarm beklenir (dataset’e göre değişebilir)." -ForegroundColor DarkGray

# Son üretilen raporu kök target/report.* olarak yayınla (IDE sekmeleri için)
try {
  if ($summary.Count -gt 0) {
    $last = $summary[-1]
    if ($last.html -and (Test-Path $last.html)) {
      Copy-Item -Force $last.html -Destination (Join-Path $repoRoot 'target\report.html')
    }
    if ($last.pdf -and (Test-Path $last.pdf)) {
      Copy-Item -Force $last.pdf -Destination (Join-Path $repoRoot 'target\report.pdf')
    }
  }
} catch {
  Write-Host "[publish] Rapor kopyalanamadı: $($_.Exception.Message)" -ForegroundColor DarkYellow
}
