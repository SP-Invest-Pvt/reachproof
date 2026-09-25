#!/usr/bin/env bash
# End-to-end: demo product scan -> ground-truth check -> external real-world check -> example sign-off.
#   ./scripts/run_all.sh                          engine only, no API key needed
#   LLM=gemini GEMINI_API_KEY=... ./scripts/run_all.sh   adds the LLM second opinion
#   LLM=ollama ./scripts/run_all.sh               local model (after scripts/setup_ollama.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PYTHON:-python3}
LLM_ARGS=()
if [ -n "${LLM:-}" ]; then
  LLM_ARGS=(--llm "$LLM")
  [ -n "${MODEL:-}" ] && LLM_ARGS+=(--model "$MODEL")
fi
rm -rf results && mkdir -p results

./scripts/fetch_realworld.sh
echo; echo "== 1. Scan the demo product"
$PY -m reachproof scan examples/acme-shop/product.json -o results/acme-shop ${LLM_ARGS[@]+"${LLM_ARGS[@]}"}

echo; echo "== 2. Check decisions against the demo's ground truth"
$PY -m reachproof evaluate examples/acme-shop/product.json --expected examples/acme-shop/expected.json \
    -o results/eval-acme-shop ${LLM_ARGS[@]+"${LLM_ARGS[@]}"} | tee results/eval-acme-shop.txt

echo; echo "== 3. External check on third-party code (christophetd/log4shell-vulnerable-app)"
$PY -m reachproof evaluate examples/real-world/log4shell-vulnerable-app/product.json \
    --expected examples/real-world/log4shell-vulnerable-app/expected.json \
    -o results/eval-log4shell-app ${LLM_ARGS[@]+"${LLM_ARGS[@]}"} | tee results/eval-log4shell-app.txt

echo; echo "== 4. Example sign-off (demo reviewer) and Article 14 clock"
$PY -m reachproof decide --run results/acme-shop --id "notify-worker|CVE-2021-44228" --status affected \
    --by "Demo Reviewer" --note "User-Agent header reaches log.info at WebhookController.java:27."
$PY -m reachproof decide --run results/acme-shop --id "billing-batch|CVE-2023-46604" --status not_affected \
    --justification vulnerable_code_not_in_execute_path --by "Demo Reviewer" \
    --note "activemq-client is never imported; removal ticket raised."
$PY -m reachproof clock --run results/acme-shop
$PY -m reachproof verify --run results/acme-shop
echo; echo "Done. Open results/acme-shop/dossier.html"
