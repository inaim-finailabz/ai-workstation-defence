#!/usr/bin/env bash
# Verify AI Workstation Defence yourself, on macOS or Linux.
#
#   ./scripts/verify.sh
#
# Builds from source, runs every test, replays a sample session, checks the
# log, and runs that same session with the network cut off.
# Nothing here needs root, and nothing touches your real files.

set -euo pipefail
cd "$(dirname "$0")/.."

pass() { printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
skip() { printf '  \033[33mSKIP\033[0m  %s\n' "$1"; }
step() { printf '\n== %s\n' "$1"; }

step "1. Build from source (exact dependency versions from Cargo.lock)"
cargo build --release --locked
AWD="$PWD/target/release/awd"
pass "built $AWD"

step "2. Run every test (unit, end-to-end, trust)"
cargo test --locked --workspace
pass "all tests passed"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

step "3. Replay the sample session and read the report"
"$AWD" watch --source replay --input examples/sample-session.jsonl --data-dir "$WORK/data" --home /Users/ana >/dev/null
"$AWD" report --data-dir "$WORK/data" --home /Users/ana
pass "report produced"

step "4. Check the log, then tamper with it"
"$AWD" verify --data-dir "$WORK/data"
cp -R "$WORK/data" "$WORK/cut"
head -n 5 "$WORK/data/activity.log" > "$WORK/cut/activity.log"
if "$AWD" verify --data-dir "$WORK/cut"; then
  echo "cutting off the newest entries was NOT detected"; exit 1
fi
pass "cutting off the newest entries was detected"
sed 's/cart.ts/cart.js/' "$WORK/data/activity.log" > "$WORK/edited" && cat "$WORK/edited" > "$WORK/data/activity.log"
if "$AWD" verify --data-dir "$WORK/data"; then
  echo "tampering was NOT detected"; exit 1
fi
pass "a one-character edit was detected"

step "5. Run with all network access denied"
run_all() {
  "$AWD" watch --source replay --input examples/sample-session.jsonl --data-dir "$WORK/net" --home /Users/ana >/dev/null &&
  "$AWD" report --data-dir "$WORK/net" --home /Users/ana >/dev/null &&
  "$AWD" verify --data-dir "$WORK/net" >/dev/null
}
case "$(uname -s)" in
  Darwin)
    if command -v sandbox-exec >/dev/null; then
      rm -rf "$WORK/net"
      export -f run_all; export AWD WORK
      sandbox-exec -p '(version 1)(allow default)(deny network*)' bash -c run_all
      pass "the replayed session ran inside a macOS sandbox that denies all network access"
    else
      skip "sandbox-exec not available"
    fi
    ;;
  Linux)
    if command -v strace >/dev/null; then
      rm -rf "$WORK/net"
      strace -f -e trace=network -o "$WORK/trace" bash -c "$(declare -f run_all); AWD='$AWD' WORK='$WORK' run_all"
      if grep -E 'AF_INET6?' "$WORK/trace"; then
        echo "network activity detected"; exit 1
      fi
      pass "strace saw no internet sockets (AF_INET/AF_INET6) during the replayed session"
    else
      skip "strace not installed (sudo apt install strace)"
    fi
    if command -v unshare >/dev/null && unshare -rn true 2>/dev/null; then
      rm -rf "$WORK/net"
      unshare -rn bash -c "$(declare -f run_all); AWD='$AWD' WORK='$WORK' run_all"
      pass "the replayed session ran inside a namespace with no network at all"
    else
      skip "unprivileged network namespaces unavailable"
    fi
    ;;
esac

step "Done"
echo "  Every check above ran on your machine, from source you can read."
echo "  They cover a replayed session. Live capture is not exercised here: see docs/TESTING.md."
