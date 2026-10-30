package io.github.dflippojr.fhircrdrouter.client.internal;

/**
 * Shared SDK implementation detail: removes a credential the payer echoes back from an error body
 * before a {@link io.github.dflippojr.fhircrdrouter.client.PayerCallException} keeps it (#195).
 * Redact the whole body before the exception truncates it, so a credential cut at the limit leaves
 * no prefix behind.
 */
public final class EchoedCredentials {
    public static final String MARKER = "[REDACTED]";

    private EchoedCredentials() { }

    /** {@code body} with every occurrence of each non-empty credential replaced by {@link #MARKER}. */
    public static String redact(String body, String... credentials) {
        if (body == null) {
            return null;
        }
        String safe = body;
        for (String credential : credentials) {
            if (credential != null && !credential.isEmpty()) {
                safe = safe.replace(credential, MARKER);
            }
        }
        return safe;
    }

    /** The credential in an {@code Authorization} header value: what follows the scheme, or the whole value. */
    public static String fromAuthorization(String header) {
        if (header == null) {
            return null;
        }
        int space = header.indexOf(' ');
        return space > 0 ? header.substring(space + 1) : header;
    }
}
