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
# Usage: corpus-edit-check.sh <base-ref>     (locally: origin/master)
# Exit:  0 pass, 1 corpus edited without an escape hatch, 2 usage or git error
set -euo pipefail

CORPUS_DIRS=(
  client-sdk/src/test/resources/coverage-information/cases/
  client-sdk/src/test/resources/crd-ri/
)
KNOWN_DIFFERENCES=client-sdk/src/test/resources/coverage-information/known-differences.json
DECISIONS=DECISIONS.md

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

edited=()
escape_hatch=""

# -z: NUL-separated, so no path quoting. A rename or copy entry carries two
# paths (old, then new); every other entry carries one.
diff_out="$(git diff --name-status -z -M "$merge_base" HEAD | tr '\0' '\n')" || exit 2
mapfile -t fields <<< "$diff_out"
i=0
while (( i < ${#fields[@]} )); do
  status="${fields[i]}"
  [[ -z "$status" ]] && { i=$((i + 1)); continue; }
  path="${fields[i + 1]:-}"
  case "$status" in
    R* | C*)
      new_path="${fields[i + 2]:-}"
      i=$((i + 3))
      ;;
    *)
      new_path="$path"
      i=$((i + 2))
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
      in_corpus "$path" && edited+=("renamed  $path -> $new_path")
      ;;
    D*)
      in_corpus "$path" && edited+=("deleted  $path")
      ;;
    *)
      in_corpus "$path" && edited+=("modified $path")
      ;;
  esac
done

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
