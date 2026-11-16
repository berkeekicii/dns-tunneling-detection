param(
  [string]$alerts   = "target\alerts.ndjson",
  [string]$out      = "target\report.html",
  [switch]$MaskPII  # mask qname: show only root
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path $alerts)) { throw "alerts not found: $alerts" }

# Metadata
$ts        = Get-Date -Format "yyyy-MM-dd HH:mm:ssK"
$hash      = (Get-FileHash -Algorithm SHA256 $alerts).Hash
$modelFile = "models/iforest.onnx"
$modelHash = if (Test-Path $modelFile) { (Get-FileHash -Algorithm SHA256 $modelFile).Hash } else { $null }

# Read NDJSON (skip blank)
$lines = Get-Content $alerts | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_ | ConvertFrom-Json }

# Summaries
$total = @($lines).Count
$byReasonTag = $lines | Group-Object reason | Sort-Object Count -Descending
$byRoot      = $lines | Group-Object root   | Sort-Object Count -Descending | Select-Object -First 10

# Distinct reason combinations (null-safe)
$reasonKeys = $lines | ForEach-Object {
  if ($_ -and $_.PSObject.Properties.Name -contains 'reasons' -and $_.reasons) { ($_.reasons) -join '+' } else { $null }
}
$distinctReasonComb = @($reasonKeys | Where-Object { $_ } | Group-Object | Select-Object -ExpandProperty Name).Count

# Additional KPIs
$distinctRoots   = @($lines | ForEach-Object { $_.root } | Where-Object { $_ } | Sort-Object -Unique).Count
$distinctQnames  = @($lines | ForEach-Object { $_.qname } | Where-Object { $_ } | Sort-Object -Unique).Count
$rulesOnlyCnt    = @($lines | Where-Object { $_.reason -eq 'rules' }).Count
$mlOnlyCnt       = @($lines | Where-Object { $_.reason -eq 'ml' }).Count
$bothCnt         = @($lines | Where-Object { $_.reason -eq 'both' }).Count
$noneCnt         = @($lines | Where-Object { $_.reason -eq 'none' }).Count
$mlTaggedCnt     = @($lines | Where-Object { $_.reasons -and ($_.reasons -contains 'ml_iforest') }).Count
$mlScores        = @($lines | Where-Object { $_.PSObject.Properties.Name -contains 'ml_score' -and $_.ml_score -ne $null } | Select-Object -ExpandProperty ml_score)
$mlAvg           = if ($mlScores.Count -gt 0) { [Math]::Round(($mlScores | Measure-Object -Average).Average, 4) } else { $null }
$mlMin           = if ($mlScores.Count -gt 0) { [Math]::Round(($mlScores | Measure-Object -Minimum).Minimum, 4) } else { $null }
$mlMax           = if ($mlScores.Count -gt 0) { [Math]::Round(($mlScores | Measure-Object -Maximum).Maximum, 4) } else { $null }
$ruleScores      = @($lines | Select-Object -ExpandProperty score -ErrorAction SilentlyContinue)
$ruleAvg         = if ($ruleScores.Count -gt 0) { [Math]::Round(($ruleScores | Measure-Object -Average).Average, 4) } else { $null }
$mlThreshold     = ($lines | Where-Object { $_.ml -and $_.ml.threshold -ne $null } | Select-Object -First 1).ml.threshold

# HTML template (English)
$head = @"
<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNS Tunneling Incident Report</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#222}
 h1{margin:0 0 8px 0}
 .meta{color:#555;margin-bottom:16px}
 table{border-collapse:collapse;width:100%}
 th,td{border:1px solid #e5e5e5;padding:8px;font-size:14px}
 th{background:#fafafa;text-align:left;position:sticky;top:0}
 tr:nth-child(even){background:#fcfcfc}
 .pill{padding:2px 8px;border-radius:999px;background:#eef;border:1px solid #dde}
 code{font-family:Consolas,monospace}
 .sub{color:#666;font-size:13px}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin:12px 0 24px 0}
 .card{border:1px solid #e5e5e5;padding:12px;border-radius:8px;background:#fff}
 .card h3{margin:0 0 6px 0;font-size:16px}
 .kpi{display:flex;gap:10px;flex-wrap:wrap}
 .kpi div{background:#f7f7f7;border:1px solid #e5e5e5;border-radius:6px;padding:6px 10px}
</style>
"@

$hdr = @"
<h1>DNS Tunneling Incident Report</h1>
<div class="meta">
  <div><b>Generated:</b> $ts</div>
  <div><b>Source file:</b> $alerts</div>
  <div><b>SHA256($([IO.Path]::GetFileName($alerts))):</b> <code>$hash</code></div>
  <div><b>Model SHA256:</b> <code>$modelHash</code></div>
  <div class="kpi">
    <div><b>Total alerts:</b> $total</div>
    <div><b>Distinct roots:</b> $distinctRoots</div>
    <div><b>Distinct qnames:</b> $distinctQnames</div>
    <div><b>Reason combos:</b> $distinctReasonComb</div>
    <div><b>Rules only:</b> $rulesOnlyCnt</div>
    <div><b>ML only:</b> $mlOnlyCnt</div>
    <div><b>Both:</b> $bothCnt</div>
    <div><b>ML tagged:</b> $mlTaggedCnt</div>
    <div><b>ML threshold:</b> $mlThreshold</div>
    <div><b>Avg rule score:</b> $ruleAvg</div>
    <div><b>Avg ML score:</b> $mlAvg</div>
  </div>
  <div class="sub">Note: PII masking: $($MaskPII.IsPresent)</div>
</div>

<div class="grid">
  <div class="card">
    <h3>Reason distribution (rules/ml/both/none)</h3>
    <div>
      $(($byReasonTag | ForEach-Object { "<div><b>$($_.Name)</b>: $($_.Count)</div>" }) -join "")
    </div>
  </div>
  <div class="card">
    <h3>Top roots</h3>
    <div>
      $(($byRoot | ForEach-Object { "<div><b>$([System.Web.HttpUtility]::HtmlEncode($_.Name))</b>: $($_.Count)</div>" }) -join "")
    </div>
  </div>
  <div class="card">
    <h3>Diversity</h3>
    <div>Distinct reason combinations: <b>$distinctReasonComb</b></div>
    <div>ML score range: <b>$mlMin</b> .. <b>$mlMax</b></div>
  </div>
</div>

<table>
  <tr>
    <th>time</th><th>qname</th><th>root</th><th>qtype</th>
    <th>score</th><th>ml_score</th><th>reasons</th>
    <th>len</th><th>H</th><th>txt</th><th>nx</th><th>qps</th><th>uniq_sub</th>
  </tr>
"@

# HtmlEncode
Add-Type -AssemblyName System.Web

function Mask-Domain([string]$qname,[string]$root){ if (-not $qname) { return $qname } if ($MaskPII) { return $root } return $qname }
function Fmt([double]$x){ if ($null -eq $x) { return '' } return ([string]::Format('{0:0.###}',$x)) }
function FmtTs([long]$sec){ try { return ([DateTimeOffset]::FromUnixTimeSeconds($sec)).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss') } catch { return $sec } }

$rows = foreach ($a in $lines) {
  $reasons = if ($a.reasons) { ($a.reasons | ForEach-Object { "<span class='pill'>$_</span>" }) -join " " } else { '' }
  $q = Mask-Domain -qname $a.qname -root $a.root
  $len = if ($a.PSObject.Properties.Name -contains 'domain_len') { $a.domain_len } else { '' }
  $h   = if ($a.PSObject.Properties.Name -contains 'entropy')    { Fmt $a.entropy } else { '' }
  $t   = if ($a.PSObject.Properties.Name -contains 'txt_ratio')  { Fmt $a.txt_ratio } else { '' }
  $nx  = if ($a.PSObject.Properties.Name -contains 'nx_ratio')   { Fmt $a.nx_ratio } else { '' }
  $qps = if ($a.PSObject.Properties.Name -contains 'qps_client') { Fmt $a.qps_client } else { '' }
  $us  = if ($a.PSObject.Properties.Name -contains 'unique_sub_ratio') { Fmt $a.unique_sub_ratio } else { '' }
  "<tr>" +
  "<td>$(FmtTs $a.ts)</td>" +
  "<td>$([System.Web.HttpUtility]::HtmlEncode($q))</td>" +
  "<td>$([System.Web.HttpUtility]::HtmlEncode($a.root))</td>" +
  "<td>$([System.Web.HttpUtility]::HtmlEncode($a.qtype))</td>" +
  "<td>$(Fmt $a.score)</td>" +
  "<td>$(Fmt $a.ml_score)</td>" +
  "<td>$reasons</td>" +
  "<td>$len</td>" +
  "<td>$h</td>" +
  "<td>$t</td>" +
  "<td>$nx</td>" +
  "<td>$qps</td>" +
  "<td>$us</td>" +
  "</tr>"
}

@($head,"<body>",$hdr) + $rows + @("</table>","</body>") |
  Set-Content -Encoding UTF8 $out

Write-Host "OK - wrote $out"

