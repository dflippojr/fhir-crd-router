package io.github.dflippojr.fhircrdrouter.core.audit;

/** No corrupt line contents, paths or parser exception text are exposed. */
public final class AuditReadException extends RuntimeException {
    private final long lineNumber;
    AuditReadException(long lineNumber) {
        super("Cannot read audit history at line " + lineNumber);
        this.lineNumber = lineNumber;
    }
    public long lineNumber() { return lineNumber; }
}
