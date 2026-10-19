# examples-quickstart

Runnable end-to-end demo, wired against an in-process mock CDS Hooks server
(`MockCdsHooksServer`) rather than a real payer sandbox, since there's no
live payer to point a personal project at.

```sh
./mvnw install -DskipTests          # once, so the sibling modules resolve
./mvnw -pl examples-quickstart exec:java
```

(Don't add `-am` to the second command — that runs `exec:java` in every
upstream module too, and those have no main class.)

What it does:

1. Starts the mock server on `localhost:8089`.
2. Loads `sample-connections.yaml` into a `FileBasedConnectionStore` in an
   owner-only temp directory (which also holds the encrypted credential store).
3. Resolves `DEMO-PAYER` via `PayerRouter`.
4. Calls `discoverServices(...)` and `callHook(...)` against the mock server
   through the real `CdsHooksClient`, printing one metadata-only line per HTTP
   exchange (`PayerExchangeListener.metadataOnly`).

Swap `sample-connections.yaml` for a real payer's sandbox `baseUrl` (and set
`authType`/`credentialRef` appropriately) once you have one to test against.

CI runs these same commands on Linux with JDK 21 after the full `verify`
gate. Run `bash .github/scripts/quickstart-smoke.sh` from the repository root
to repeat the smoke check: it checks the exit status, two discovery GETs
(connection verification and explicit discovery), one hook POST, and the
absence of stack traces and credential material. The sample uses `NONE`
authentication, so there are currently no sample credential values to scan.
