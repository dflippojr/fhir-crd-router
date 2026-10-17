#!/usr/bin/env bash
# Runs the official HL7 FHIR validator over the coverage-information corpus and
# every FHIR resource embedded in the test fixtures, and rewrites the recorded
# verdicts. CI's fhir-validator job runs this and fails if the verdicts change.
#
#   fhir-validator/run.sh
#
# Needs bash, curl, jq, sha256sum and Java 17+ (JAVA, or java on PATH). The jar
# is cached in FHIR_VALIDATOR_CACHE (default ~/.cache/fhir-validator) and FHIR
# packages in ~/.fhir/packages. The first run downloads about 40 packages.
set -euo pipefail

# Pinned release of hapifhir/org.hl7.fhir.core, and the SHA-256 of its
# validator_cli.jar asset. Bump both together, then rerun and review the
# verdict diff.
VALIDATOR_VERSION=7.0.2
VALIDATOR_SHA256=e3e50f06b806437821b7aef8189a1b790415cb96c5036e0812ed62981452b377
# The CRD version this repo targets (CRD 2.2.1, https://hl7.org/fhir/us/davinci-crd/STU2.2/).
IG=hl7.fhir.us.davinci-crd#2.2.1

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CORPUS=client-sdk/src/test/resources/coverage-information
FIXTURES=(client-sdk/src/test/resources/crd-ri/*.json examples-quickstart/src/main/resources/mock-payer/*.json)
JAVA=${JAVA:-java}

cache=${FHIR_VALIDATOR_CACHE:-$HOME/.cache/fhir-validator}/$VALIDATOR_VERSION
jar=$cache/validator_cli.jar
if [ ! -f "$jar" ]; then
  mkdir -p "$cache"
  curl -sSfL -o "$jar.part" \
    "https://github.com/hapifhir/org.hl7.fhir.core/releases/download/$VALIDATOR_VERSION/validator_cli.jar"
  mv "$jar.part" "$jar"
fi
echo "$VALIDATOR_SHA256  $jar" | sha256sum -c -

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/in"

cd "$ROOT"
# Corpus cases are whole resources, validated as they are.
for f in "$CORPUS"/cases/*.json; do
  cp "$f" "$work/in/case@$(basename "$f")"
done
# Fixtures are CDS Hooks envelopes (no FHIR profile, out of scope); validate the
# outermost resources inside them. A resource's name is its fixture and JSON path.
for f in "${FIXTURES[@]}"; do
  while IFS=$'\t' read -r at resource; do
    printf '%s\n' "$resource" > "$work/in/fixture@$(basename "$f" .json)@$at.json"
  done < <(jq -r '
    . as $doc
    | [paths(objects and has("resourceType"))] as $all
    | $all[] as $p
    | select(any($all[]; length < ($p | length) and $p[:length] == .) | not)
    | [($p | map(tostring) | join(".")), ($doc | getpath($p) | tojson)]
    | @tsv' "$f")
done

(cd "$work/in" && "$JAVA" "-Xmx${FHIR_VALIDATOR_XMX:-4g}" -jar "$jar" ./*.json \
  -version 4.0.1 -ig "$IG" -tx n/a -allow-example-urls true -output "$work/out.json") > "$work/log.txt" 2>&1 || {
  # The validator exits non-zero when any input has errors; only a missing
  # report is a failure of the run itself.
  [ -s "$work/out.json" ] || { tail -n 50 "$work/log.txt"; exit 1; }
}
# Set FHIR_VALIDATOR_REPORT to keep the full report, warnings included.
[ -z "${FHIR_VALIDATOR_REPORT:-}" ] || cp "$work/out.json" "$FHIR_VALIDATOR_REPORT"

# One verdict per input: valid when it has no error or fatal issues, plus those
# issues sorted so the file is stable between runs.
verdicts() {
  local prefix=$1
  jq --arg prefix "$prefix" --arg validator "$VALIDATOR_VERSION" --arg ig "$IG" '
    (if .resourceType == "Bundle" then [.entry[].resource] else [.] end)
    | map({
        name: ((.extension[] | select(.url | endswith("operationoutcome-file")) | .valueString)
               | sub("^.*[/\\\\]"; "")),
        errors: ([.issue[] | select(.severity == "error" or .severity == "fatal") | {
          location: ((.expression // .location // ["(none)"])[0]),
          messageId: ((.extension // []) | map(select(.url | endswith("operationoutcome-message-id")) | .valueCode)
                      | first // "(none)"),
          message: .details.text
        }] | unique)
      })
    | map(select(.name | startswith($prefix)))
    | map({key: (.name | ltrimstr($prefix) | rtrimstr(".json")), value: {valid: (.errors == []), errors}})
    | sort_by(.key)
    | {validator: $validator, ig: $ig, verdicts: from_entries}' "$work/out.json"
}
verdicts "case@" > "$CORPUS/official-verdicts.json"
verdicts "fixture@" > fhir-validator/fixture-verdicts.json

count() { jq '.verdicts | length' "$1"; }
echo "validator $VALIDATOR_VERSION, $IG: $(count "$CORPUS/official-verdicts.json") corpus cases," \
  "$(count fhir-validator/fixture-verdicts.json) fixture resources"
expected=$(( $(ls "$CORPUS"/cases/*.json | wc -l) ))
[ "$(count "$CORPUS/official-verdicts.json")" -eq "$expected" ] || {
  echo "validator reported on $(count "$CORPUS/official-verdicts.json") of $expected corpus cases" >&2; exit 1; }
