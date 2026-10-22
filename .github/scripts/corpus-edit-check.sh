#!/usr/bin/env bash
# Fails when the commits since <base-ref> modify, rename or delete a corpus
# case without also changing an escape hatch (#131). It enforces AGENTS.md,
# step 3: "Never edit a case to make it agree." The fhir-validator and crd-ri
# jobs catch a changed verdict, but not a case rewritten so both sides agree.
#
# Corpus:        client-sdk/src/test/resources/coverage-information/cases/
#                client-sdk/src/test/resources/crd-ri/
# Escape hatches: client-sdk/src/test/resources/coverage-information/known-differences.json
#                DECISIONS.md
#
# Added cases are always allowed. A deleted case passes when the same diff
# changes DECISIONS.md, like any other edit. The diff runs from the merge base
# of <base-ref> and HEAD to HEAD, so only committed changes count.
#
# CI runs this file from the base commit, not from the pull request, and the
# pull request's checkout is only the repository it inspects (DECISIONS.md,
# "Corpus edit check"). So a pull request may change this file or its test, but
# it may not delete or rename either one: the base would then have no checker,
# and the next pull request would run its own copy.
#
# Usage: corpus-edit-check.sh <base-ref>     (locally: origin/master)
# Exit:  0 pass, 1 corpus or checker edited, 2 usage or git error
set -euo pipefail

CORPUS_DIRS=(
  client-sdk/src/test/resources/coverage-information/cases/
  client-sdk/src/test/resources/crd-ri/
)
KNOWN_DIFFERENCES=client-sdk/src/test/resources/coverage-information/known-differences.json
DECISIONS=DECISIONS.md
CHECKER_FILES=(
  .github/scripts/corpus-edit-check.sh
  .github/scripts/corpus-edit-check-test.sh
)

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <base-ref>   (for example: $0 origin/master)" >&2
  exit 2
fi
base_ref="$1"

if ! merge_base="$(git merge-base "$base_ref" HEAD)"; then
  echo "error: no merge base between '$base_ref' and HEAD; fetch the base branch (with history) first" >&2
  exit 2
fi

in_corpus() {
  local dir
  for dir in "${CORPUS_DIRS[@]}"; do
    [[ "$1" == "$dir"* ]] && return 0
  done
  return 1
}

is_checker() {
  local file
  for file in "${CHECKER_FILES[@]}"; do
    [[ "$1" == "$file" ]] && return 0
  done
  return 1
}

# A path as one shell-quoted word, so a newline in a file name can't start a
# line of its own (or a workflow command) in the output.
quote() {
  printf '%q' "$1"
}

edited=()
removed_checker=()
escape_hatch=""

# -z: each field ends in a NUL and no path is quoted. A rename or copy record
# is status, old path, new path; every other record is status, path. The
# fields are read NUL by NUL: a file name may contain a newline, so turning
# NULs into newlines would let a name such as $'a\nM\nDECISIONS.md' pose as
# extra records. The output goes to a file first so that git's exit status
# is not lost in a pipe.
diff_file="$(mktemp)"
trap 'rm -f "$diff_file"' EXIT
git diff --name-status -z -M "$merge_base" HEAD > "$diff_file" || exit 2

truncated() {
  echo "error: git diff output ended inside a record" >&2
  exit 2
}

while IFS= read -r -d '' status; do
  IFS= read -r -d '' path || truncated
  case "$status" in
    R* | C*)
      IFS= read -r -d '' new_path || truncated
      ;;
    *)
      new_path="$path"
      ;;
  esac

  if [[ "$path" == "$KNOWN_DIFFERENCES" || "$path" == "$DECISIONS" \
     || "$new_path" == "$KNOWN_DIFFERENCES" || "$new_path" == "$DECISIONS" ]]; then
    escape_hatch="$new_path"
  fi

  case "$status" in
    A* | C*)
      # A new case, or a copy that leaves the original in place.
      ;;
    R*)
      # Renaming a case out of (or within) the corpus removes the old one.
      in_corpus "$path" && edited+=("renamed  $(quote "$path") -> $(quote "$new_path")")
      is_checker "$path" && removed_checker+=("renamed  $path -> $(quote "$new_path")")
      ;;
    D*)
      in_corpus "$path" && edited+=("deleted  $(quote "$path")")
      is_checker "$path" && removed_checker+=("deleted  $path")
      ;;
    *)
      in_corpus "$path" && edited+=("modified $(quote "$path")")
      ;;
  esac
done < "$diff_file"

if (( ${#removed_checker[@]} > 0 )); then
  {
    echo "::error::corpus-edit: the corpus edit check itself is deleted or renamed."
    printf '  %s\n' "${removed_checker[@]}"
    echo
    echo "CI runs the check from the base commit. Without it there, the next pull"
    echo "request would run its own copy. No escape hatch allows this; to retire"
    echo "the check, remove the corpus-edit job from .github/workflows/ci.yml first,"
    echo "which the gate guard leaves to the owner (DECISIONS.md, \"Corpus edit check\")."
  } >&2
  exit 1
fi

if (( ${#edited[@]} == 0 )); then
  echo "corpus-edit: no existing corpus case changed since $base_ref."
  exit 0
fi

if [[ -n "$escape_hatch" ]]; then
  echo "corpus-edit: ${#edited[@]} corpus case(s) changed, allowed because $escape_hatch also changed:"
  printf '  %s\n' "${edited[@]}"
  exit 0
fi

{
  echo "::error::corpus-edit: ${#edited[@]} existing corpus case(s) changed without an escape hatch."
  printf '  %s\n' "${edited[@]}"
  echo
  echo "Never edit a case to make it agree (AGENTS.md, step 3). Adding a case is"
  echo "always allowed. To change or remove an existing case, record why in the same"
  echo "pull request, in one of:"
  echo "  $KNOWN_DIFFERENCES"
  echo "  $DECISIONS"
} >&2
exit 1
