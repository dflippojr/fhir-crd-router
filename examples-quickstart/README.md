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
2. Loads `sample-connections.yaml` into a temp `FileBasedConnectionStore`.
3. Resolves `DEMO-PAYER` via `PayerRouter`.
4. Calls `discoverServices(...)` and `callHook(...)` against the mock server
   through the real `CdsHooksClient`.

Swap `sample-connections.yaml` for a real payer's sandbox `baseUrl` (and set
`authType`/`credentialRef` appropriately) once you have one to test against.
