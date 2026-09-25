# Windows equivalent of run_all.sh.   .\scripts\run_all.ps1 [-Llm gemini|anthropic|openai|ollama] [-Model name]
param([string]$Llm = "", [string]$Model = "")
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$llmArgs = @()
if ($Llm) { $llmArgs += @("--llm", $Llm); if ($Model) { $llmArgs += @("--model", $Model) } }
if (Test-Path results) { Remove-Item results -Recurse -Force }
New-Item -ItemType Directory results | Out-Null
$dest = "examples/real-world/log4shell-vulnerable-app/src"
if (-not (Test-Path "$dest/.git")) {
  git clone -q https://github.com/christophetd/log4shell-vulnerable-app.git $dest
  git -C $dest checkout -q c962aabb31a6af0a77f0e9bbc7100e175c7c04e1
}
& $py -m reachproof scan examples/acme-shop/product.json -o results/acme-shop @llmArgs
& $py -m reachproof evaluate examples/acme-shop/product.json --expected examples/acme-shop/expected.json -o results/eval-acme-shop @llmArgs | Tee-Object -Variable out1
$out1 | Out-File -Encoding utf8 results/eval-acme-shop.txt
& $py -m reachproof evaluate examples/real-world/log4shell-vulnerable-app/product.json --expected examples/real-world/log4shell-vulnerable-app/expected.json -o results/eval-log4shell-app @llmArgs | Tee-Object -Variable out2
$out2 | Out-File -Encoding utf8 results/eval-log4shell-app.txt
& $py -m reachproof decide --run results/acme-shop --id "notify-worker|CVE-2021-44228" --status affected --by "Demo Reviewer" --note "User-Agent header reaches log.info at WebhookController.java:27."
& $py -m reachproof decide --run results/acme-shop --id "billing-batch|CVE-2023-46604" --status not_affected --justification vulnerable_code_not_in_execute_path --by "Demo Reviewer" --note "activemq-client is never imported; removal ticket raised."
& $py -m reachproof clock --run results/acme-shop
& $py -m reachproof verify --run results/acme-shop
Write-Host "Done. Open results/acme-shop/dossier.html"
