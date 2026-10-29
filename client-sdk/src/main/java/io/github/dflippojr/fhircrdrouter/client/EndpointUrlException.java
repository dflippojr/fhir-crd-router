package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.core.RouterException;

/**
 * A URL on a {@link io.github.dflippojr.fhircrdrouter.core.ConnectionRecord} that the SDK will not
 * use: placeholder until #156 is implemented.
 */
public final class EndpointUrlException extends RouterException {
    private final String field;
    private final String payerId;

    public EndpointUrlException(String field, String payerId, String problem) {
        super(field + " for payerId=" + payerId + " " + problem);
        this.field = field;
        this.payerId = payerId;
    }

    public String field() { return field; }
    public String payerId() { return payerId; }
}
