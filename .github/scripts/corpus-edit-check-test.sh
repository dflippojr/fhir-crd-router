#!/usr/bin/env bash
# Tests corpus-edit-check.sh (#131) in throwaway git repos: one base commit
# with a corpus and both escape hatches, then one pull-request commit per case.
# Run by CI's corpus-edit job; locally: bash .github/scripts/corpus-edit-check-test.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$HERE/corpus-edit-check.sh"
SELF="$HERE/$(basename "${BASH_SOURCE[0]}")"
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
# new_repo <name> with-checker also commits this checker and its test to the
# base, at the paths CI runs them from.
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
  if [[ "${2:-}" == with-checker ]]; then
    mkdir -p .github/scripts
    cp "$CHECK" .github/scripts/corpus-edit-check.sh
    cp "$SELF" .github/scripts/corpus-edit-check-test.sh
  fi
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
  local name="$1" want="$2"
  shift 2
  expect_from "$CHECK" "$name" "$want" "$@"
}

# expect_from <checker> <name> <exit code> [text]...: runs that copy of the check.
expect_from() {
  local check="$1" name="$2" want="$3" out code=0 text
  shift 3
  ran=$((ran + 1))
  out="$(bash "$check" master 2>&1)" || code=$?
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

# A file name may contain a newline. Read as lines, the NUL-separated records
# of this added file, A|a<LF>M<LF>DECISIONS.md, pose as A|a then M|DECISIONS.md:
# an escape hatch that never changed.
new_repo newline-added
echo '{"case": "covered", "edited": true}' > "$CASES/code-covered.json"
echo 'not a decision' > $'a\nM\nDECISIONS.md'
commit_pr
expect "an added file whose name fakes a DECISIONS.md record does not unlock the check" 1 \
  "modified $CASES/code-covered.json"

new_repo newline-renamed
echo '{"case": "covered", "edited": true}' > "$CASES/code-covered.json"
git mv README.md $'README\nM\nDECISIONS.md'
commit_pr
expect "a renamed file whose name fakes a DECISIONS.md record does not unlock the check" 1 \
  "modified $CASES/code-covered.json"

new_repo newline-renamed-case
git mv "$CASES/date-month-13.json" "$CASES/"$'x\nM\nDECISIONS.md'
commit_pr
expect "a case renamed to a name that fakes a DECISIONS.md record fails, the name quoted" 1 \
  "renamed  $CASES/date-month-13.json -> $(printf '%q' "$CASES/"$'x\nM\nDECISIONS.md')"

# CI runs the check from the base commit, checked out apart from the pull
# request (ci.yml, corpus-edit). A pull request that edits a case and turns the
# checker and its test into no-ops still fails under the base's copy, though
# its own copy would pass.
new_repo tampered with-checker
echo '{"case": "covered", "edited": true}' > "$CASES/code-covered.json"
printf '#!/usr/bin/env bash\nexit 0\n' > .github/scripts/corpus-edit-check.sh
printf '#!/usr/bin/env bash\nexit 0\n' > .github/scripts/corpus-edit-check-test.sh
commit_pr
git worktree add -q --detach "$work/tampered-base" master
expect_from "$work/tampered-base/.github/scripts/corpus-edit-check.sh" \
  "a pull request that no-ops the checker and its test still fails under the base's copy" 1 \
  "modified $CASES/code-covered.json"
expect_from .github/scripts/corpus-edit-check.sh \
  "(control) the pull request's no-op copy would have passed it" 0

new_repo checker-modified with-checker
echo '# a comment' >> .github/scripts/corpus-edit-check.sh
commit_pr
expect "a pull request may change the checker, which runs from the base" 0 \
  "no existing corpus case changed"

new_repo checker-deleted with-checker
git rm -q .github/scripts/corpus-edit-check.sh
echo '## Why the check went away' >> DECISIONS.md
commit_pr
expect "deleting the checker fails, even with DECISIONS.md" 1 \
  "deleted  .github/scripts/corpus-edit-check.sh"

new_repo checker-test-renamed with-checker
git mv .github/scripts/corpus-edit-check-test.sh .github/scripts/old-test.sh
commit_pr
expect "renaming the checker's test fails" 1 \
  "renamed  .github/scripts/corpus-edit-check-test.sh -> .github/scripts/old-test.sh"

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
