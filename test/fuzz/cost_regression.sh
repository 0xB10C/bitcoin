#!/usr/bin/env bash
# Regression gate: replay one corpus through two builds of a cost-metered fuzz
# target and fail if any input got more expensive. Point BASE_BIN and HEAD_BIN
# at two commits' `fuzz` binaries (both built with -DFUZZ_COST=ON).
#
#   BASE_BIN=../base/build_fuzz_nosan/bin/fuzz \
#   HEAD_BIN=build_fuzz_nosan/bin/fuzz \
#   test/fuzz/cost_regression.sh p2p_deserialize_cost block .cache/full/block/corpus
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET=${1:?target}; TYPE=${2:-}; CORPUS=${3:?corpus dir}
BASE_BIN=${BASE_BIN:?set BASE_BIN}; HEAD_BIN=${HEAD_BIN:?set HEAD_BIN}
RATIO=${RATIO:-1.5}
tmp=$(mktemp -d)
python3 "$HERE/cost_replay.py" --bin "$BASE_BIN" --target "$TARGET" ${TYPE:+--type "$TYPE"} --corpus "$CORPUS" --out "$tmp/base.json"
python3 "$HERE/cost_replay.py" --bin "$HEAD_BIN" --target "$TARGET" ${TYPE:+--type "$TYPE"} --corpus "$CORPUS" --out "$tmp/head.json"
python3 "$HERE/cost_diff.py" "$tmp/base.json" "$tmp/head.json" --ratio "$RATIO"
