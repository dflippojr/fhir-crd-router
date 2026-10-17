# Agent instructions

Read `README.md` for what the modules do and `DECISIONS.md` for why they are
built the way they are. Requires JDK 17+; use the bundled `./mvnw`.

## How to prove a change works

A PR is not done until it shows proof. Running one test class with `-Dtest=`
is a useful loop while you work, but it is not proof.

1. **Run the full gate.** This is what CI's `build` job runs on JDK 17 and 21:

   ```sh
   ./mvnw -B -ntp verify
   ```

   `verify` runs every test and the JaCoCo coverage floor (line and branch,
   per module, set in each module's `pom.xml`). If the floor fails, add tests;
   never lower a floor. When coverage rises, raise the floor to the new value
   minus 0.01. On a PR, the required check is `gate`, which passes only when
   the `build` matrix, the `sonar` quality gate and the `fhir-validator` job
   (step 3) all pass.

2. **Run the reference server** when a change touches the client SDK's wire
   behaviour: requests, responses, discovery, prefetch, auth or the CRD
   models. It runs the client against the HL7 Da Vinci CRD reference
   implementation, at a pinned commit:

   ```sh
   docker build -t crd-ri https://github.com/HL7-DaVinci/CRD.git#43547c4e69052df4d3532972e4bd03f8d5317d13
   docker run -d --name crd-ri -p 18090:8090 crd-ri
   CRD_RI_BASE_URL=http://127.0.0.1:18090/r4 ./mvnw -pl client-sdk -am test
   docker rm -f crd-ri
   ```

   Wait for `curl -sf http://127.0.0.1:18090/r4/cds-services` to answer
   before running the tests. Without `CRD_RI_BASE_URL`,
   `CrdReferenceServerTest` is skipped, so check that its tests ran.

3. **Run the official FHIR validator** when a change touches
   `CoverageInformationValidator`, the corpus in
   `client-sdk/src/test/resources/coverage-information/`, or a fixture with
   FHIR resources in it (`crd-ri/*.json`, the quickstart's `mock-payer/*.json`).
   CI's `fhir-validator` job runs the same script and fails if a verdict
   changes:

   ```sh
   JAVA=<path to a JDK 17+ java> fhir-validator/run.sh
   git diff -- '*verdicts.json'
   ```

   A changed verdict is a finding, not noise. Fix the validator, or record the
   difference in `known-differences.json` with a DECISIONS.md entry or a bug
   issue. Never edit a case to make it agree.

4. **Cite the spec.** A change to spec behaviour cites the section it
   implements: [CRD 2.2.1](https://hl7.org/fhir/us/davinci-crd/STU2.2/) or
   [CDS Hooks](https://cds-hooks.hl7.org/2.0/). Put the link in the PR and in
   a comment next to the code. The validators (`CdsDiscoveryValidator`,
   `CoverageInformationValidator`) are hand-written from the spec, so a
   citation is how a reviewer checks them.

5. **Start a bug fix with a failing test.** Write a test that fails on
   `master`, show it failing, then fix the code. Put the red and green runs
   in the PR.

6. **Fill the `## Proof` table** in the PR template: one row per acceptance
   criterion, with the command or test that verified it and the evidence
   (an output excerpt, a red-before and green-after pair, or a link). Fill
   `### Not verified` and `### Gate changes` too, even if only to say
   "none".
