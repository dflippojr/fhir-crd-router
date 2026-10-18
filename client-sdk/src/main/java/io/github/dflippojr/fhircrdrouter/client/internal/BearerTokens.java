package io.github.dflippojr.fhircrdrouter.client.internal;

import java.util.regex.Pattern;

/** Shared SDK implementation detail: what may follow {@code Bearer } in an Authorization header. */
public final class BearerTokens {
    /** RFC 6750 section 2.1: b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=". */
    private static final Pattern B64TOKEN = Pattern.compile("[A-Za-z0-9._~+/-]+=*");

    private BearerTokens() { }

    /**
     * Whether {@code value} is an RFC 6750 {@code b64token}. Anything else, such as a control
     * character, a trailing newline or a character above U+00FF, cannot be sent as a bearer token.
     */
    public static boolean isB64Token(String value) {
        return value != null && B64TOKEN.matcher(value).matches();
    }
}
