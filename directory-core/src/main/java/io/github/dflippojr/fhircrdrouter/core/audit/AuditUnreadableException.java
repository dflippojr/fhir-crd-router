package io.github.dflippojr.fhircrdrouter.core.audit;

/** The trail could not be opened or read (I/O failure); it says nothing about the file's content. */
public final class AuditUnreadableException extends RuntimeException {
    AuditUnreadableException() {
        // No cause or path: OS errors can contain file locations.
        super("Cannot open or read the audit trail");
    }
}
