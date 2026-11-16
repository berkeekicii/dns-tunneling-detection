Param(
  [string]$JsonList = ".\data\dns-lab-10q.json",
  [string]$Alerts   = ".\target\alerts.ndjson",
  [double]$ScoreMin = 0.40
)

function Normalize([string]$s){
  if ([string]::IsNullOrWhiteSpace($s)) { return $s }
  return $s.Trim().TrimEnd('.').ToLower()
}

if (!(Test-Path $JsonList)) { throw "Liste yok: $JsonList" }
if (!(Test-Path $Alerts))   { throw "Alert dosyası yok: $Alerts (önce analizi çalıştır)" }

$lists = Get-Content $JsonList | ConvertFrom-Json
$bad   = @($lists.bad)  | ForEach-Object { Normalize $_ }
$good  = @($lists.good) | ForEach-Object { Normalize $_ }

# NDJSON satırlarını oku
$rows = Get-Content $Alerts | ForEach-Object { $_ | ConvertFrom-Json }
$rows = $rows | ForEach-Object {
  [pscustomobject]@{
    qname   = (Normalize $_.qname)
    score   = $_.score
    reasons = $_.reasons
  }
}

# 1) Kötüler alarm verdi mi?
$hi = $rows | Where-Object { $_.score -ge $ScoreMin }
$badResult = foreach($b in $bad){
  $hit = $hi | Where-Object { $_.qname -eq $b }
  [pscustomobject]@{
    qname   = $b
    alarm   = ($hit.Count -gt 0)
    score   = ($hit | Sort-Object score -Descending | Select-Object -First 1).score
    reasons = (($hit | Select-Object -First 1).reasons -join ",")
  }
}

# 2) İyiler alarm vermedi mi?
$goodResult = foreach($g in $good){
  $hit = $hi | Where-Object { $_.qname -eq $g }
  [pscustomobject]@{
    qname = $g
    alarm = ($hit.Count -gt 0)
  }
}

# 3) En az 3 farklı reason kombinasyonu var mı?
$reasonKeys = $hi | ForEach-Object { (($_.reasons) -join "+") } |
              Group-Object | Select-Object -ExpandProperty Name
$distinctReasons = @($reasonKeys).Count

Write-Host "`n=== KÖTÜ (alarm beklenir) ===" -ForegroundColor Yellow
$badResult | Format-Table

Write-Host "`n=== İYİ (alarm beklenmez) ===" -ForegroundColor Green
$goodResult | Format-Table

$badOK  = ($badResult | Where-Object { $_.alarm -eq $true }).Count -eq $bad.Count
$goodOK = ($goodResult | Where-Object { $_.alarm -eq $true }).Count -eq 0
$reOK   = ($distinctReasons -ge 3)

Write-Host ("`nÖZET -> badOK:{0}  goodOK:{1}  reasonVariety(>=3):{2}" -f $badOK,$goodOK,$reOK) -ForegroundColor Cyan

if(!$badOK -or !$goodOK -or !$reOK){ exit 1 } else { exit 0 }
