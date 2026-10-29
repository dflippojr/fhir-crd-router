package io.github.dflippojr.fhircrdrouter.client.internal;

import io.github.dflippojr.fhircrdrouter.client.EndpointUrlException;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Shared SDK implementation detail: the one rule for every URL on a {@link ConnectionRecord}
 * ({@code baseUrl}, {@code tokenEndpoint}, {@code jwksUrl}). A URL must be absolute, have a host and
 * use {@code https}; {@code http} is allowed only to a loopback host ({@code localhost},
 * {@code 127.0.0.0/8}, {@code [::1]}), for local payers, reference servers and tests.
 *
 * <p>CDS Hooks 2.0, <a href="https://cds-hooks.hl7.org/2.0/#security-and-safety">Security and Safety</a>:
 * "All data exchanged through the RESTful APIs MUST be transmitted over channels secured using the
 * Hypertext Transfer Protocol (HTTP) over Transport Layer Security (TLS)". Over {@code http} the JDK
 * presents no client certificate, so a configured {@code mtlsCredentialRef} would not help either.
 */
public final class EndpointUrls {
    /** A dotted-quad in 127.0.0.0/8, each octet 0-255 without leading zeros. */
    private static final Pattern IPV4_LOOPBACK = Pattern.compile(
            "127(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}");

    private EndpointUrls() { }

    /**
     * The URL as a {@link URI}, or an {@link EndpointUrlException} naming {@code field} and the payer.
     * The exception never repeats the URL, which may carry userinfo or a query with a secret in it.
     */
    public static URI require(ConnectionRecord record, String field, String value) {
        if (value == null || value.isBlank()) {
            throw refused(record, field, "is not set");
        }
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException e) {
            throw refused(record, field, "is not a valid URI");
        }
        if (!uri.isAbsolute()) {
            throw refused(record, field, "is not an absolute URI");
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("https") && !scheme.equals("http")) {
            throw refused(record, field, "must be an https URL");
        }
        if (uri.getHost() == null) {
            throw refused(record, field, "has no host");
        }
        if (scheme.equals("http") && !isLoopback(uri.getHost())) {
            throw refused(record, field, "must use https: http is allowed only to a loopback host");
        }
        return uri;
    }

    /** True for {@code localhost}, an IPv4 literal in 127.0.0.0/8 or a loopback IPv6 literal; never a DNS name. */
    static boolean isLoopback(String host) {
        String lower = host.toLowerCase(Locale.ROOT);
        if (lower.equals("localhost") || IPV4_LOOPBACK.matcher(lower).matches()) {
            return true;
        }
        if (lower.startsWith("[") && lower.endsWith("]")) {
            try {
                // A bracketed IPv6 literal is parsed, never looked up.
                return InetAddress.getByName(lower).isLoopbackAddress();
            } catch (UnknownHostException e) {
                return false;
            }
        }
        return false;
    }

    private static EndpointUrlException refused(ConnectionRecord record, String field, String problem) {
        return new EndpointUrlException(field, record.payerId(), problem);
    }
}
