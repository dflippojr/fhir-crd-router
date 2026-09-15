package io.github.dflippojr.fhircrdrouter.core;

/** Thrown when a payer connection cannot be resolved or persisted. */
public class RouterException extends RuntimeException {

    public RouterException(String message) {
        super(message);
    }

    public RouterException(String message, Throwable cause) {
        super(message, cause);
    }
}
