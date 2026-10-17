#!/usr/bin/env bash
# Reports one run of the downstream workflow (.github/workflows/downstream.yml).
#
# On success it writes the tested SHAs to the job summary. On failure it opens,
# or comments on, the one open issue titled "$ISSUE_TITLE", with the failing
# tests and the first failing commit range. With DRY_RUN=true it writes the
# issue it would open to the job summary (and stdout) instead.
#
# Inputs (environment):
#   REPO              owner/name of this repo
#   RUN_URL           link to this workflow run
#   ROUTER_DIR        checkout of this repo, with full history
#   ROUTER_SHA        fhir-crd-router commit that was installed
#   WORKBENCH_SHA     payer-onboarding-workbench commit that was built
#   LOG_DIR           holds install.log, verify.log and demo.log
#   INSTALL_OUTCOME, VERIFY_OUTCOME, DEMO_OUTCOME
#                     step outcomes: success, failure, cancelled or skipped
#   DRY_RUN           true to print the issue instead of filing it
#   GITHUB_STEP_SUMMARY  set by Actions; defaults to stdout
#   GH_TOKEN          for gh; needs issues: write and actions: read
#   LAST_GOOD_RUN     optional: "<run id> <router sha>" of the last successful
#                     run, to skip the gh lookup (local dry runs)
set -euo pipefail

ISSUE_TITLE="Downstream: workbench fails against master"
WORKFLOW_FILE="downstream.yml"
WORKBENCH_REPO="dflippojr/payer-onboarding-workbench"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

short() { printf '%s' "${1:0:12}"; }

if [ "$INSTALL_OUTCOME" = success ] && [ "$VERIFY_OUTCOME" = success ] && [ "$DEMO_OUTCOME" = success ]; then
  {
    echo "## Downstream: workbench passes against master"
    echo
    echo "- fhir-crd-router: \`$ROUTER_SHA\`"
    echo "- payer-onboarding-workbench: \`$WORKBENCH_SHA\`"
    echo
    echo "\`./mvnw verify\` and \`node scripts/demo.mjs\` passed in the workbench."
  } >> "$SUMMARY"
  exit 0
fi

# Matches surefire failures, compile errors and the failed goal, in log order.
failure_lines() {
  local log="$1"
  [ -f "$log" ] || return 0
  sed -e 's/\x1b\[[0-9;]*m//g' "$log" \
    | grep -E '<<< (FAILURE|ERROR)!|^\[ERROR\]   [^ ]|^\[ERROR\] .*\.java:\[[0-9]+,[0-9]+\]|^\[ERROR\] Failed to execute goal|^\[ERROR\] Tests run:' \
    | sed -e "s#${GITHUB_WORKSPACE:-/nonexistent}/##g" \
    | head -n 60 || true
}

# "<run id> <head sha>" of the newest successful scheduled or dispatched run on master.
last_good_run() {
  if [ -n "${LAST_GOOD_RUN:-}" ]; then
    printf '%s\n' "$LAST_GOOD_RUN"
    return
  fi
  gh run list -R "$REPO" --workflow "$WORKFLOW_FILE" --branch master --status success \
    --limit 1 --json databaseId,headSha --jq '.[] | "\(.databaseId) \(.headSha)"' 2>/dev/null || true
}

# The workbench SHA a successful run built, from the artifact that run uploaded.
workbench_sha_of_run() {
  local tmp
  tmp="$(mktemp -d)"
  if gh run download "$1" -R "$REPO" -n downstream-tested -D "$tmp" > /dev/null 2>&1 \
    && [ -f "$tmp/workbench-sha.txt" ]; then
    tr -d '[:space:]' < "$tmp/workbench-sha.txt"
  fi
  rm -rf "$tmp"
}

body="$(mktemp)"
{
  echo "The nightly [downstream check]($RUN_URL) built [payer-onboarding-workbench](https://github.com/$WORKBENCH_REPO) against this repo and it failed."
  echo
  echo "| | |"
  echo "|---|---|"
  echo "| fhir-crd-router | \`$ROUTER_SHA\` |"
  echo "| payer-onboarding-workbench | \`$WORKBENCH_SHA\` |"
  echo "| \`./mvnw install\` (this repo) | $INSTALL_OUTCOME |"
  echo "| \`./mvnw verify\` (workbench) | $VERIFY_OUTCOME |"
  echo "| \`node scripts/demo.mjs\` (workbench) | $DEMO_OUTCOME |"
  echo

  for step in install verify; do
    lines="$(failure_lines "$LOG_DIR/$step.log")"
    if [ -n "$lines" ]; then
      echo "### Failing tests and errors (\`$step\`)"
      echo
      echo '```'
      printf '%s\n' "$lines"
      echo '```'
      echo
    fi
  done
  if [ "$DEMO_OUTCOME" = failure ] && [ -f "$LOG_DIR/demo.log" ]; then
    echo "### Demo output (last 40 lines)"
    echo
    echo '```'
    sed -e 's/\x1b\[[0-9;]*m//g' "$LOG_DIR/demo.log" | tail -n 40
    echo '```'
    echo
  fi

  echo "### First failing commit range"
  echo
  read -r good_run good_sha <<< "$(last_good_run)" || true
  if [ -z "${good_sha:-}" ]; then
    echo "No earlier successful run of \`$WORKFLOW_FILE\` on \`master\`, so there is no known-good commit."
    echo "The range is everything up to \`$(short "$ROUTER_SHA")\`."
  elif [ "$good_sha" = "$ROUTER_SHA" ]; then
    echo "fhir-crd-router is unchanged since the [last passing run](https://github.com/$REPO/actions/runs/$good_run) (\`$(short "$good_sha")\`)."
  else
    echo "fhir-crd-router [\`$(short "$good_sha")...$(short "$ROUTER_SHA")\`](https://github.com/$REPO/compare/$good_sha...$ROUTER_SHA): \`$(short "$good_sha")\` passed in the [last passing run](https://github.com/$REPO/actions/runs/$good_run)."
    echo
    echo '```'
    git -C "$ROUTER_DIR" log --oneline --no-decorate -n 30 "$good_sha..$ROUTER_SHA" 2>/dev/null \
      || echo "(could not list the commits; see the compare link)"
    echo '```'
  fi
  if [ -n "${good_run:-}" ]; then
    good_workbench="$(workbench_sha_of_run "$good_run")"
    echo
    if [ -z "$good_workbench" ]; then
      echo "The last passing run did not record which workbench commit it built."
    elif [ "$good_workbench" = "$WORKBENCH_SHA" ]; then
      echo "The workbench is unchanged since the last passing run, so the cause is in this repo."
    else
      echo "The workbench also changed since the last passing run: [\`$(short "$good_workbench")...$(short "$WORKBENCH_SHA")\`](https://github.com/$WORKBENCH_REPO/compare/$good_workbench...$WORKBENCH_SHA)."
    fi
  fi
  echo
  echo "The workbench pins an older commit in \`scripts/install-crd-router.sh\`; this check overrides that pin with \`master\`. Fix the break here, or record the API change so the workbench can follow it when it bumps the pin."
} > "$body"

if [ "${DRY_RUN:-false}" = true ]; then
  {
    echo "## Downstream: workbench fails against master (dry run)"
    echo
    echo "Dry run: no issue was opened or commented on. This is the issue body it would file, titled **$ISSUE_TITLE**:"
    echo
    echo "---"
    echo
    cat "$body"
  } >> "$SUMMARY"
  [ "$SUMMARY" = /dev/stdout ] || cat "$body"
  rm -f "$body"
  exit 0
fi

existing="$(gh issue list -R "$REPO" --state open --search "in:title \"$ISSUE_TITLE\"" --json number,title \
  --jq "map(select(.title == \"$ISSUE_TITLE\")) | .[0].number // empty")"
if [ -n "$existing" ]; then
  url="$(gh issue comment "$existing" -R "$REPO" --body-file "$body")"
  action="Commented on"
else
  url="$(gh issue create -R "$REPO" --title "$ISSUE_TITLE" --body-file "$body")"
  action="Opened"
fi
{
  echo "## Downstream: workbench fails against master"
  echo
  echo "$action $url"
  echo
  cat "$body"
} >> "$SUMMARY"
rm -f "$body"
