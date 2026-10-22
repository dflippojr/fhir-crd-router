#!/usr/bin/env bash
# Tests corpus-edit-check.sh (#131) in throwaway git repos: one base commit
# with a corpus and both escape hatches, then one pull-request commit per case.
# Run by CI's corpus-edit job; locally: bash .github/scripts/corpus-edit-check-test.sh
set -euo pipefail

CHECK="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/corpus-edit-check.sh"
CASES=client-sdk/src/test/resources/coverage-information/cases
CRD_RI=client-sdk/src/test/resources/crd-ri
KNOWN_DIFFERENCES=client-sdk/src/test/resources/coverage-information/known-differences.json

# Keep the user's and the system's git config (hooks, signing, renames) out.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid

work="$(mktemp -d "${TMPDIR:-/tmp}/corpus-edit-test.XXXXXX")"
trap 'rm -rf "$work"' EXIT

failures=0
ran=0

# Fresh repo on master with the corpus, then a "pr" branch checked out.
new_repo() {
  local dir="$work/$1"
  git init -q -b master "$dir"
  cd "$dir"
  mkdir -p "$CASES" "$CRD_RI"
  echo '{"case": "covered"}' > "$CASES/code-covered.json"
  echo '{"case": "date"}' > "$CASES/date-month-13.json"
  echo '{"fixture": "bed"}' > "$CRD_RI/order-sign-hospital-bed.json"
  echo '[]' > "$KNOWN_DIFFERENCES"
  echo '# Decisions' > DECISIONS.md
  echo 'readme' > README.md
  git add -A
  git commit -q -m base
  git checkout -q -b pr
}

commit_pr() {
  git add -A
  git commit -q --allow-empty -m pr
}

# expect <name> <exit code> [text the output must contain]...
expect() {
  local name="$1" want="$2" out code=0 text
  shift 2
  ran=$((ran + 1))
  out="$(bash "$CHECK" master 2>&1)" || code=$?
  if [[ "$code" != "$want" ]]; then
    echo "FAIL $name: exit $code, want $want"
    printf '%s\n' "$out" | sed 's/^/    /'
    failures=$((failures + 1))
    return
  fi
  for text in "$@"; do
    if [[ "$out" != *"$text"* ]]; then
      echo "FAIL $name: output lacks '$text'"
      printf '%s\n' "$out" | sed 's/^/    /'
      failures=$((failures + 1))
      return
    fi
  done
  echo "ok   $name (exit $code)"
}

new_repo modified
echo '{"case": "covered", "edited": true}' > "$CASES/code-covered.json"
echo '{"fixture": "bed", "edited": true}' > "$CRD_RI/order-sign-hospital-bed.json"
commit_pr
expect "modified cases without an escape hatch fail and are named" 1 \
  "modified $CASES/code-covered.json" \
  "modified $CRD_RI/order-sign-hospital-bed.json" \
  "$KNOWN_DIFFERENCES" "DECISIONS.md"

new_repo modified-known-differences
echo '{"case": "covered", "edited": true}' > "$CASES/code-covered.json"
echo '[{"case": "code-covered.json"}]' > "$KNOWN_DIFFERENCES"
commit_pr
expect "modified case with known-differences.json passes" 0 \
  "allowed because $KNOWN_DIFFERENCES also changed"

new_repo modified-decisions
echo '{"fixture": "bed", "edited": true}' > "$CRD_RI/order-sign-hospital-bed.json"
echo '## Why the bed fixture changed' >> DECISIONS.md
commit_pr
expect "modified case with DECISIONS.md passes" 0 \
  "allowed because DECISIONS.md also changed"

new_repo added
echo '{"case": "new"}' > "$CASES/code-new.json"
echo '{"fixture": "new"}' > "$CRD_RI/order-sign-new.json"
commit_pr
expect "added cases pass" 0 "no existing corpus case changed"

new_repo no-corpus
echo 'more readme' >> README.md
commit_pr
expect "no corpus change passes" 0 "no existing corpus case changed"

new_repo no-commits
expect "no commits since the base passes" 0 "no existing corpus case changed"

new_repo deleted
git rm -q "$CASES/date-month-13.json"
commit_pr
expect "deleted case without an escape hatch fails" 1 \
  "deleted  $CASES/date-month-13.json"

new_repo deleted-decisions
git rm -q "$CASES/date-month-13.json"
echo '## Why date-month-13 was removed' >> DECISIONS.md
commit_pr
expect "deleted case with DECISIONS.md passes" 0 \
  "deleted  $CASES/date-month-13.json"

new_repo renamed
git mv "$CASES/date-month-13.json" "$CASES/date-month-thirteen.json"
commit_pr
expect "renamed case without an escape hatch fails" 1 \
  "renamed  $CASES/date-month-13.json -> $CASES/date-month-thirteen.json"

new_repo base-moved
echo '{"case": "covered", "edited": true}' > "$CASES/code-covered.json"
commit_pr
git checkout -q master
echo '{"case": "covered", "edited on master": true}' > "$CASES/code-covered.json"
echo '## A master-only decision' >> DECISIONS.md
git commit -q -am "master moves on"
git checkout -q pr
expect "the diff runs from the merge base, not the moved base tip" 1 \
  "modified $CASES/code-covered.json"

new_repo usage
ran=$((ran + 1))
code=0
bash "$CHECK" > /dev/null 2>&1 || code=$?
if [[ "$code" == 2 ]]; then
  echo "ok   no base ref is a usage error (exit 2)"
else
  echo "FAIL no base ref: exit $code, want 2"
  failures=$((failures + 1))
fi
ran=$((ran + 1))
code=0
bash "$CHECK" no-such-ref > /dev/null 2>&1 || code=$?
if [[ "$code" == 2 ]]; then
  echo "ok   an unknown base ref is an error (exit 2)"
else
  echo "FAIL unknown base ref: exit $code, want 2"
  failures=$((failures + 1))
fi

echo "$ran cases, $failures failed"
[[ "$failures" == 0 ]]
