# Optional local audit foundation

The `core.audit` package is an opt-in facility for host-established attribution and
owner inspection. Existing store, router and SDK constructors remain audit-disabled.
This foundation does not instrument actions; coverage belongs to #40. There is no
server, web page, identity system or new dependency.

`AuditContext` names the initiating host caller: CLIENT, SYSTEM, ANONYMOUS or
HOST_ADMINISTRATOR. Legacy calls use `AuditContext.unknown()`. The host must derive
attribution from its trusted execution/authentication boundary, never an actor
header or request-supplied name. Payer/clientId and clinical context.userId do not
authenticate the initiating caller. Context is immutable and supplied per operation;
share the same correlation UUID for its attempt and completion, never a mutable
global actor. Optional on-behalf-of IDs describe host-established delegation.

IDs must be opaque, non-sensitive labels (1-128 ASCII letters/digits, dots,
underscores or hyphens, beginning with a letter/digit). This syntax rejects URI,
PEM and control-character payloads; it cannot determine whether an otherwise valid
string is a secret or patient ID. Hosts must enforce that semantic boundary.
Action, target kind and changed field names use the same syntax; at most 64 field
names are accepted. No payload, headers, values, exception text or credential
contents are accepted. Never serialize a PayerExchange or clinical object into
this trail. Validation errors do not echo rejected input. Jackson encodes JSON;
each line contains a schema-v1 event and its SHA-256 checksum, with ISO UTC Instant,
fresh event UUID, context, action, target, optional environment, outcome and field
names. Collections are immutable.

## Host protocol

Create the protected parent directory yourself. Configure a persistent path,
not a quickstart temporary directory. One writer/process may own the file;
the writer takes an exclusive file lock and serializes in-process appends.

```java
var context = new AuditContext(AuditContext.ActorKind.SYSTEM, "host-app", null,
        AuditContext.Source.JOB, UUID.randomUUID());
try (var trail = new JsonlAuditTrail(Path.of("private-audit/events.jsonl"), Clock.systemUTC())) {
    trail.record(context, "example.operation", "connection", "synthetic-payer-1",
            Environment.SANDBOX, AuditEvent.Outcome.ATTEMPTED, List.of());
    // Host performs its action exactly once and captures the result here.
    trail.record(context, "example.operation", "connection", "synthetic-payer-1",
            Environment.SANDBOX, AuditEvent.Outcome.SUCCEEDED, List.of("status"));
    // Use FAILED instead of SUCCEEDED when the action failed; never include its exception.
}
```

Both attempt and completion appends are forced with `FileChannel.force(true)`.
`AuditPersistenceException` provides event/correlation IDs and operation state:
ATTEMPT_NOT_RECORDED means the host action has not yet run; stop and report the gap.
COMPLETED_ACTION_AUDIT_FAILED means an action result already exists and its audit
completion could not be confirmed. Never retry the side effect because of this
error. Errors carry no underlying exception text or sensitive cause. A failed
append/force may nevertheless have persisted bytes, so durability remains uncertain.
The writer is poisoned after failure and will reject further appends. Construction
and close failures use IOException (corrupt history uses AuditReadException).

The action and audit file are not an atomic transaction. A lone ATTEMPTED means
unknown completion, not failure. Crashes before attempt, between attempt and action,
after action before completion, or during force leave different gaps. Hosts must
reconcile against their own state. Power loss/filesystem/hardware behavior can lose
unforced data; force is not a promise against hardware failure, nor does it force
parent-directory metadata for a newly created file. No automatic replay is provided.

## Owner-run offline inspection

Run this Java code inside an owner/admin process with directory-core on its
classpath (imports from `core.audit`, `java.nio.file`, `java.time`, `java.util`).
The reader has no append, update, delete or purge methods:

```java
var reader = new AuditReader(Path.of("private-audit/events.jsonl"));
var query = new AuditQuery(Instant.parse("2026-10-08T00:00:00Z"),
        Instant.parse("2026-10-09T00:00:00Z"), null, "host-app",
        null, null, null, null, 100);
var result = reader.query(query);
result.events().forEach(System.out::println);
System.out.println("Incomplete tail: " + result.incompleteFinalLine());
System.out.println("More matching events: " + result.limitReached());
// Secure the export destination with the same owner-only policy before opening it.
try (var out = Files.newOutputStream(Path.of("private-audit/export.jsonl"),
        StandardOpenOption.CREATE_NEW)) {
    reader.exportJsonl(query, out);
}
```

Time ranges are inclusive from/exclusive to. Optional actor kind/ID, target kind/ID,
action and correlation UUID filters combine with AND. Limits are 1-10000; results
are oldest first in append order. The entire file is scanned and validated even
after the result limit, with at most 64 KiB per line and bounded retained results.
Export contains the same safe checksummed events; it returns the query result so
tail/limit warnings remain visible. The host secures and owns the export stream.

Only newline-terminated records are committed history. An unterminated final line
is excluded explicitly via `incompleteFinalLine`, even if it looks like complete
JSON. All preceding valid history is returned. Invalid complete lines (including
checksum/schema errors) throw AuditReadException with a line number and no content.
The writer refuses to reopen an incomplete tail or corrupt file; it never truncates
or repairs history. The owner must preserve the damaged file in a protected archive,
inspect/reconcile the gap, then configure a new file. Readers should inspect a
quiescent file or backup: a live reader can observe an in-progress append as a tail.
Missing files return empty results; read errors are reported.

## Permissions, retention, backup and integrity

Only the designated host administrator/OS owner may inspect the trail. POSIX files
are created atomically with mode 0600 and existing files are restricted to 0600.
On Windows the ACL is replaced with an owner-only ALLOW entry with all file rights;
creation initially inherits the parent ACL, so the parent **must already be private**.
Tests exercise POSIX modes on supported systems and Windows ACLs on Windows. Other
filesystems without either permission model are rejected. No parent directories
are created, and final-path symlinks are rejected. Hosts must protect parent paths
against substitution, and secure directory modes/ACLs themselves. Existing reader
access is governed by the OS; Java callers running as the owner share that access.
The library does not invent ACLs for ordinary host application users.

There is **no automatic deletion in v1**. The owner chooses archive/purge policy;
do not infer a healthcare compliance period. Keep the configured path across
restarts and close the writer before backup/copy/rotation. Include the audit file
separately in protected backups alongside host state; export is bounded and may
not be a full backup. Restoring an older backup rolls the trail back: later events
are lost, and no separate journal survives restore. The owner must coordinate
host-state and trail restore. Backups/exports need equivalent permissions.

The app API is append-only. Checksums detect accidental corruption, not tampering:
there is no hash chain, signature, secret key or external anchor. The process/OS
owner remains trusted and can edit, delete, recompute checksums or replace files
and backups outside this boundary. No tamper-proof or tamper-evidence claim is made.
