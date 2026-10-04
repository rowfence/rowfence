#!/bin/bash
# test.sh: the editors' side, each in a container:
#   - the Tree-sitter grammar (tree-sitter-authz): src/ is what grammar.js generates, its corpus passes, and
#     every .authz file in the repository parses without an error, the queries included
#   - the Zed extension builds (WebAssembly, as Zed builds it)
# Needs Docker and bash (Git Bash works on Windows).
set -u
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
REPO=$(pwd -W 2>/dev/null || pwd)
rc=0
ok() { echo "ok    $1"; }
bad() { echo "FAIL  $1"; rc=1; }
# on Linux, as the caller: what the containers write in the checkout stays removable
as_me=(); [ "$(uname -s)" = Linux ] && as_me=(-u "$(id -u):$(id -g)" -e HOME=/tmp)

echo "-- the grammar"
docker run --rm "${as_me[@]}" -v "$REPO:/repo" -w /repo/editor/tree-sitter-authz node:24-trixie bash -c '
  npm ci --no-audit --no-fund >/dev/null 2>&1 || { echo "FAIL  npm ci"; exit 1; }
  rm -rf /tmp/src && cp -r src /tmp/src && npx tree-sitter generate >/dev/null 2>&1 &&
    diff -r /tmp/src src >/dev/null && echo "ok    src/ is what grammar.js generates" ||
    { echo "FAIL  src/ is not what grammar.js generates: run npx tree-sitter generate"; exit 1; }
  npx tree-sitter test >/tmp/corpus.log 2>&1 && echo "ok    the corpus" || { cat /tmp/corpus.log; exit 1; }
  files=$(find /repo -name "*.authz" -not -path "*/node_modules/*" -not -path "*/.venv/*" | sort)
  npx tree-sitter parse -q $files 2>/dev/null && echo "ok    every policy in the repository parses ($(echo "$files" | wc -l) files)" ||
    { npx tree-sitter parse -q $files; echo "FAIL  a policy has a parse error"; exit 1; }
  for q in queries/*.scm; do
    npx tree-sitter query -q "$q" $files >/dev/null 2>/tmp/query.log || { cat /tmp/query.log; echo "FAIL  $q"; exit 1; }
  done && echo "ok    the queries run on them"
' || rc=1

echo "-- the Zed extension"
docker run --rm "${as_me[@]}" -e CARGO_HOME=/tmp/cargo -v "$REPO:/repo" -w /repo/editor/zed rust:1 bash -c '
  cp -r /usr/local/cargo /tmp/cargo 2>/dev/null
  rustup target add wasm32-wasip2 >/dev/null 2>&1 &&
    cargo build -q --release --target wasm32-wasip2 --target-dir /tmp/target 2>&1 &&
    ls /tmp/target/wasm32-wasip2/release/rowfence_zed.wasm >/dev/null' \
  && ok "it builds for wasm32-wasip2" || bad "the Zed extension doesn't build"

exit $rc
