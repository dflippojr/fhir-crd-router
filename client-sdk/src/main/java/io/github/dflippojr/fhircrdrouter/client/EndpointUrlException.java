package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.core.RouterException;

/**
 * A URL on a {@link io.github.dflippojr.fhircrdrouter.core.ConnectionRecord} that the SDK will not
 * use: not an absolute {@code http} or {@code https} URI with a host, or {@code http} to a host that
 * is not loopback. Thrown before any credential is read or request is sent. The message names the
 * field and the payer but never repeats the URL.
 */
public final class EndpointUrlException extends RouterException {
    private final String field;
    private final String payerId;
    private final String problem;

    public EndpointUrlException(String field, String payerId, String problem) {
        super(field + " for payerId=" + payerId + " " + problem);
        this.field = field;
        this.payerId = payerId;
        this.problem = problem;
    }

    /** The record field holding the URL: {@code baseUrl}, {@code tokenEndpoint} or {@code jwksUrl}. */
    public String field() { return field; }
    public String payerId() { return payerId; }

    /** What is wrong with the URL, without the URL itself, e.g. {@code "has no host"}. */
    public String problem() { return problem; }
}
