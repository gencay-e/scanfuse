#!/usr/bin/env bash
# Usage: run-with-annotations.sh <title> <command...>
# Runs the command. On failure, prints the failing lines as one error annotation so they show up
# in the check-run annotations as well as in the log.
set -o pipefail
title="$1"
shift
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
if "$@" 2>&1 | tee "$log"; then
  exit 0
fi
msg="$(grep -E '^(FAILED|ERROR) |^E  |: error:|^error|^[A-Z][0-9]{3} ' -A1 "$log" | head -80 | sed 's/%/%25/g' | awk '{printf "%s%%0A", $0}')"
if [[ -z "$msg" ]]; then
  msg="$(tail -40 "$log" | sed 's/%/%25/g' | awk '{printf "%s%%0A", $0}')"
fi
echo "::error title=${title} failed::${msg}"
exit 1
