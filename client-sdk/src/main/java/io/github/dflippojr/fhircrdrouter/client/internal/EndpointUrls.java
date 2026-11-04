package io.github.dflippojr.fhircrdrouter.client.internal;

import io.github.dflippojr.fhircrdrouter.client.EndpointUrlException;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
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
 *
 * <p>Only the record's URLs are checked, so the {@link HttpClient} that sends to them must not follow
 * redirects: the JDK would resend the request to the {@code Location} without this check, for example
 * from {@code https} to {@code http} ({@link #requireNoRedirects}).
 */
public final class EndpointUrls {
    /** A dotted-quad in 127.0.0.0/8, each octet 0-255 without leading zeros. */
    private static final Pattern IPV4_LOOPBACK = Pattern.compile(
            "127(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}");

    private EndpointUrls() { }

    /**
     * Every URL the SDK will use for this record: {@code baseUrl}, which must also have no query or
     * fragment, then {@link #requireTokenUrls} for OAuth2, or {@code jwksUrl} when a {@code CDS_HOOKS_JWT}
     * is signed. Call before any credential read, token fetch or request (#156).
     */
    public static void requireUsable(ConnectionRecord record) {
        URI base = require(record, "baseUrl", record.baseUrl());
        // CDS Hooks 2.0, Discovery (https://cds-hooks.hl7.org/2.0/#discovery): the SDK appends /cds-services to
        // baseUrl. After a query or fragment that suffix would land in the query or be dropped, and the request
        // would go to the base path itself.
        if (base.getRawQuery() != null || base.getRawFragment() != null) {
            throw refused(record, "baseUrl", "must not have a query or fragment");
        }
        if (record.authType() == AuthType.OAUTH2_CLIENT_CREDENTIALS
                || record.authType() == AuthType.OAUTH2_PRIVATE_KEY_JWT) {
            requireTokenUrls(record);
        } else {
            requireJwksUrl(record);
        }
    }

    /**
     * The token endpoint as a {@link URI}, after checking it and, for {@code OAUTH2_PRIVATE_KEY_JWT},
     * the {@code jwksUrl} that goes into the client assertion's {@code jku}. Call before a cached token
     * is returned or the secret is read: {@code jwksUrl} is not part of the token cache key.
     */
    public static URI requireTokenUrls(ConnectionRecord record) {
        URI endpoint = require(record, "tokenEndpoint", record.tokenEndpoint());
        requireJwksUrl(record);
        return endpoint;
    }

    /**
     * Refuses a client whose redirect policy is not {@link HttpClient.Redirect#NEVER}. A followed redirect
     * is sent by the JDK, body and headers included, to a location this class never checked: an https
     * payer answering 307 to an {@code http} URL would get the request resent in cleartext, and even
     * {@code NORMAL} lets a loopback {@code http} endpoint redirect to a remote {@code http} one.
     *
     * @throws IllegalArgumentException if {@code client} follows redirects
     */
    public static HttpClient requireNoRedirects(HttpClient client) {
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("HttpClient must not follow redirects (use HttpClient.Redirect.NEVER):"
                    + " a redirect would send the request to a URL that is not checked for https");
        }
        return client;
    }

    /** {@code jwksUrl}, when set on a record whose auth type signs a JWT that carries it as {@code jku}. */
    private static void requireJwksUrl(ConnectionRecord record) {
        boolean signsJwt = record.authType() == AuthType.CDS_HOOKS_JWT
                || record.authType() == AuthType.OAUTH2_PRIVATE_KEY_JWT;
        if (signsJwt && record.jwksUrl() != null) {
            require(record, "jwksUrl", record.jwksUrl());
        }
    }

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
