# scripts/events-to-features.ps1
Param(
  [string]$Log = "target\events.log",
  [string]$Csv = "data\features.csv",
  [string]$List= "data\dns-lab-10q.json"
)
$bad=@(); $good=@()
if (Test-Path $List) {
  $j = Get-Content $List | ConvertFrom-Json
  $bad = @($j.bad)  ; $good = @($j.good)
}
$rx = [regex]'\[dns\] seen qname=(\S+) qtype=(\S+) \| len=(\d+) labels=(\d+) H=([0-9.]+)'
$rows = Get-Content $Log | ForEach-Object {
  $m = $rx.Match($_); if($m.Success){
    [pscustomobject]@{
      qname=$m.Groups[1].Value.TrimEnd('.').ToLower()
      qtype=$m.Groups[2].Value; len=[int]$m.Groups[3].Value
      labels=[int]$m.Groups[4].Value; entropy=[double]$m.Groups[5].Value
    }
  }
}
$rows | ForEach-Object {
  $name=$_.qname
  if($bad -contains $name){ $_ | Add-Member -NotePropertyName y -NotePropertyValue 1 }
  elseif($good -contains $name){ $_ | Add-Member -NotePropertyName y -NotePropertyValue 0 }
  else { $_ | Add-Member -NotePropertyName y -NotePropertyValue $null }
  $_
} | Export-Csv -NoTypeInformation -Encoding UTF8 $Csv
