package io.github.dflippojr.fhircrdrouter.core;

/**
 * Thrown when a lookup reaches a stored connection entry that this version cannot read: a field its
 * auth type requires is missing, it has a property or an enum constant this version does not know, or
 * it is not a record at all (#231). Other payers keep resolving; only lookups that would include this
 * entry throw, so a broken record never reads as merely absent.
 *
 * <p>The message names the payer, the environment, the entry's position and the problem class (the
 * simple name of the exception that stopped the entry binding). It never carries a field value, and
 * the binding exception is not attached as the cause, because its message can quote one.
 */
public class InvalidConnectionRecordException extends RouterException {

    private final String payerId;
    private final Environment environment;
    private final String problem;

    public InvalidConnectionRecordException(String message, String payerId, Environment environment, String problem) {
        super(message);
        this.payerId = payerId;
        this.environment = environment;
        this.problem = problem;
    }

    /** The entry's {@code payerId}. */
    public String payerId() {
        return payerId;
    }

    /** The entry's environment, or {@code null} when this version cannot read it. */
    public Environment environment() {
        return environment;
    }

    /** The simple class name of the exception that stopped the entry binding. */
    public String problem() {
        return problem;
    }
}
