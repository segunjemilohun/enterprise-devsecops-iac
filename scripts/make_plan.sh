#!/usr/bin/env bash
# Generate plan.json for a fixture dir (never committed; contains plan values).
set -euo pipefail
dir="${1:?usage: make_plan.sh <tf-dir>}"
terraform -chdir="$dir" init -backend=false -input=false >/dev/null
terraform -chdir="$dir" plan -input=false -out=tfplan >/dev/null
terraform -chdir="$dir" show -json tfplan > "$dir/plan.json"
