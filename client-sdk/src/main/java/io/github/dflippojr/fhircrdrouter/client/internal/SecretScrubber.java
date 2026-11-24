package io.github.dflippojr.fhircrdrouter.client.internal;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.github.dflippojr.fhircrdrouter.client.PayerCallException;
import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

import javax.net.ssl.SSLSession;

/**
 * Shared SDK implementation detail: the functions that keep a secret out of what the SDK hands back, in an
 * exception, a {@link io.github.dflippojr.fhircrdrouter.client.PayerExchangeListener} exchange or the
 * response a {@link PayerCallException} keeps. The secrets are the EHR's {@code fhirAuthorization} token
 * (#164) and a credential the payer echoes back (#195).
 *
 * <p>Every function is pure: the secret to remove is a parameter. Nothing here reads the call's
 * {@link EhrRedaction} context, sends a request or keeps state. The classes that do read the context or send
 * ({@link ExchangeSender}, {@link EhrRedaction}, {@code CdsHooksClient}, {@code PayerCallLoop} and
 * {@code OAuth2TokenClient}) call this class, and it calls none of them (#233).
 */
public final class SecretScrubber {
    /** What a removed secret is replaced with. */
    public static final String MARKER = "[REDACTED]";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    /** Reads decimals exactly, so a redacted hook body keeps every number as it was sent. */
    private static final ObjectMapper EXACT = JsonMapper.builder()
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            // A body Jackson would read only in part (trailing text, a repeated key) is not JSON here.
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .nodeFactory(JsonNodeFactory.withExactBigDecimals(true)).build();

    private SecretScrubber() { }

    /**
     * {@code body} with every occurrence of each non-empty credential replaced by {@link #MARKER}. A credential
     * the payer echoes back in an error body is removed this way before a {@link PayerCallException} keeps the
     * body (#195): redact the whole body before the exception truncates it, so a credential cut at the limit
     * leaves no prefix behind.
     */
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

    /**
     * {@link #safeHookFailure(HttpResponse, String, String, String)} outside a call's context: only the token
     * in {@code hookBody} itself is known.
     */
    static SafeFailure safeHookFailure(HttpResponse<String> response, String body, String hookBody) {
        return safeHookFailure(response, body, hookBody, null);
    }

    /**
     * {@code response} as a {@link io.github.dflippojr.fhircrdrouter.client.PayerCallException} may keep it,
     * for a HOOK call that sent {@code hookBody} under {@code known}, the EHR token of the call's context (null
     * outside one): the EHR token is removed from its header names and values,
     * and its body is {@code body} with the token removed as for a listener (#164). A request body that
     * cannot be read, with no token known, leaves the token unknown, so the headers become empty and the body null.
     */
    public static SafeFailure safeHookFailure(HttpResponse<String> response, String body, String hookBody,
                                              String known) {
        HookBody hook = redactRequest(hookBody, known);
        if (!hook.readable()) {
            return new SafeFailure(withHeaders(response, HttpHeaders.of(Map.of(), (k, v) -> true)), null);
        }
        String token = hook.accessToken();
        if (token == null) {
            return new SafeFailure(response, body);
        }
        return new SafeFailure(withHeaders(response, redactHeaders(response.headers(), token)), redactResponse(body, token));
    }

    /** A failed response with sanitised headers, and its sanitised body. */
    public record SafeFailure(HttpResponse<String> response, String body) { }

    private static HttpResponse<String> withHeaders(HttpResponse<String> response, HttpHeaders headers) {
        return stub(response, 0, headers, null);
    }

    /** A response carrying only a status and headers, which is all a {@link PayerCallException} keeps. */
    static HttpResponse<String> status(int status, HttpHeaders headers, URI uri) {
        return stub(null, status, headers, uri);
    }

    /**
     * The one response stub here: {@code headers} and never a body. With a {@code source}, the status, request,
     * TLS session, URI and version are read from it each time they are asked for, never before; without one,
     * they are {@code status}, none, none, {@code uri} and HTTP/1.1.
     */
    private static HttpResponse<String> stub(HttpResponse<String> source, int status, HttpHeaders headers, URI uri) {
        return new HttpResponse<>() {
            @Override public int statusCode() { return source == null ? status : source.statusCode(); }
            @Override public HttpRequest request() { return source == null ? null : source.request(); }
            @Override public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            @Override public HttpHeaders headers() { return headers; }
            @Override public String body() { return null; }
            @Override public Optional<SSLSession> sslSession() {
                return source == null ? Optional.empty() : source.sslSession();
            }
            @Override public URI uri() { return source == null ? uri : source.uri(); }
            @Override public HttpClient.Version version() {
                return source == null ? HttpClient.Version.HTTP_1_1 : source.version();
            }
        };
    }

    /** Redacts request {@code Authorization}, drops {@code Set-Cookie}, and removes {@code token} from names and values. */
    static HttpHeaders safeHeaders(HttpHeaders headers, boolean request, String token) {
        Map<String, List<String>> safe = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.map().forEach((name, values) -> {
            if (request && name.equalsIgnoreCase("Authorization")) {
                safe.put(name, values.stream().map(SecretScrubber::redactAuthorization).toList());
            } else if (!name.equalsIgnoreCase("Set-Cookie")) {
                putRedacted(safe, name, values, token);
            }
        });
        return HttpHeaders.of(safe, (k, v) -> true);
    }

    /** {@code headers} with {@code token} removed from every name and value; names that then collide merge. */
    static HttpHeaders redactHeaders(HttpHeaders headers, String token) {
        Map<String, List<String>> safe = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.map().forEach((name, values) -> putRedacted(safe, name, values, token));
        return HttpHeaders.of(safe, (k, v) -> true);
    }

    /** Adds a header with {@code token} removed from its name and values; names that then collide merge. */
    static void putRedacted(Map<String, List<String>> headers, String name, List<String> values, String token) {
        headers.merge(redact(name, token),
                values.stream().map(value -> redact(value, token)).toList(),
                (a, b) -> Stream.concat(a.stream(), b.stream()).toList());
    }

    private static String redactAuthorization(String value) {
        int space = value.indexOf(' ');
        return space > 0 ? value.substring(0, space) + " [REDACTED]" : "[REDACTED]";
    }

    /**
     * A HOOK request body as a listener sees it, and the EHR access token it hid ({@code null} if none).
     * {@code readable} is false when the body could not be read, so its token, if any, is unknown.
     */
    record HookBody(String body, String accessToken, boolean readable) {
        static final HookBody UNREADABLE = new HookBody(null, null, false);

        HookBody(String body, String accessToken) {
            this(body, accessToken, true);
        }
    }

    /**
     * Replaces {@code /fhirAuthorization/access_token}, the EHR's live FHIR token
     * (<a href="https://cds-hooks.hl7.org/2.0/#passing-the-access-token-to-the-cds-service">CDS Hooks 2.0,
     * Passing the Access Token to the CDS Service</a>), with {@link #MARKER}, along with the
     * token wherever it appears in another decoded string value or key (#164). Everything else is kept. A
     * body that cannot be read as JSON (not JSON, or past Jackson's read limits) is {@link HookBody#UNREADABLE}:
     * it cannot be checked, so it and the response are omitted.
     */
    static HookBody redactFhirAuthorization(String body) {
        return redactRequest(body, null);
    }

    /**
     * {@link #redactFhirAuthorization} with {@code known}, the call's token, redacted as well; when it is
     * known, a body that cannot be read is null but still readable, since the token to look for is known.
     */
    static HookBody redactRequest(String body, String known) {
        if (body == null) {
            return new HookBody(null, known);
        }
        JsonNode json;
        try {
            json = EXACT.readTree(body);
        } catch (IOException e) {
            return known == null ? HookBody.UNREADABLE : new HookBody(null, known);
        }
        String own = null;
        boolean changed = false;
        if (json.get("fhirAuthorization") instanceof ObjectNode auth && auth.has("access_token")) {
            JsonNode token = auth.get("access_token");
            own = token.isTextual() && !token.asText().isEmpty() ? token.asText() : null;
            auth.put("access_token", MARKER);
            changed = true;
        }
        String secret = known != null ? known : own;
        if (secret == null) {
            return new HookBody(changed ? json.toString() : body, null);
        }
        changed |= scrub(json, secret) != null;
        if (own != null && !own.equals(secret)) {
            changed |= scrub(json, own) != null;
        }
        String safe = changed ? json.toString() : body;
        // Re-serialising can put characters next to each other that were apart in the decoded strings; a
        // body that still shows the token, as is or decoded, is not delivered.
        boolean survives = shows(safe, secret) || own != null && shows(safe, own);
        return new HookBody(survives ? null : safe, secret);
    }

    /**
     * Replaces {@code token} with {@link #MARKER} in every string value and key of
     * {@code node}, compared after JSON decoding, so no escape spelling hides it. Containers change in
     * place. Returns the replacement node, or null if nothing changed.
     */
    private static JsonNode scrub(JsonNode node, String token) {
        if (node.isTextual()) {
            String text = node.asText();
            return text.contains(token) ? TextNode.valueOf(text.replace(token, MARKER)) : null;
        }
        boolean changed = false;
        if (node instanceof ArrayNode array) {
            for (int i = 0; i < array.size(); i++) {
                JsonNode safe = scrub(array.get(i), token);
                if (safe != null) {
                    array.set(i, safe);
                    changed = true;
                }
            }
        } else if (node instanceof ObjectNode object) {
            Map<String, JsonNode> fields = new LinkedHashMap<>();
            for (Map.Entry<String, JsonNode> field : object.properties()) {
                JsonNode safe = scrub(field.getValue(), token);
                String name = field.getKey().replace(token, MARKER);
                changed |= safe != null || !name.equals(field.getKey());
                fields.put(name, safe == null ? field.getValue() : safe);
            }
            if (changed) {
                object.removeAll();
                object.setAll(fields);
            }
        }
        return changed ? node : null;
    }

    /**
     * A HOOK response body with {@code token} removed. A JSON body has it removed from every decoded string
     * value and key, and is re-serialised only if one changed. Any other body has the raw and JSON-escaped
     * spellings replaced; if a loose JSON decoding of what is left still shows the token, it is omitted.
     */
    static String redactResponse(String body, String token) {
        if (token == null || body == null) {
            return body;
        }
        String safe;
        try {
            JsonNode json = EXACT.readTree(body);
            JsonNode scrubbed = scrub(json, token);
            safe = scrubbed == null ? body : scrubbed.toString();
        } catch (IOException notJson) {
            safe = redactToken(body, token);
        }
        // Whatever path ran, a body that still decodes to the token is not delivered.
        return shows(safe, token) ? null : safe;
    }

    /**
     * {@code error} with the EHR token kept out of its diagnostics. A message can quote what the payer sent
     * (a malformed status line, or a parser quoting the body, say), so if any message, stack frame or
     * {@link PayerCallException} field of any cause or suppressed exception in the chain shows the token, or the token is unknown because the request could not be
     * read, this returns a copy of the same kind ({@link HttpConnectTimeoutException},
     * {@link HttpTimeoutException}, {@link InterruptedException}, otherwise {@link IOException}) whose
     * message names the original class, with the token removed, the original stack trace (any frame naming
     * the token redacted), and no cause or
     * suppressed exceptions. Otherwise it returns {@code error} itself.
     */
    public static Exception safeError(Exception error, String token, boolean unreadable) {
        if (error == null || !unreadable && (token == null || !mentions(error, token))) {
            return error;
        }
        return freshError(error, token, unreadable);
    }

    /**
     * Always a fresh copy of {@code error}, as {@link #safeError} describes, whether or not its text
     * shows the token: same kind, message naming the original class with the token removed (omitted if
     * {@code unreadable}), stack frames with the token removed, and no cause or suppressed exceptions.
     */
    static Exception freshError(Exception error, String token, boolean unreadable) {
        String message = error.getClass().getName() + ": "
                + (unreadable || token == null ? "[message omitted]" : clean(String.valueOf(error.getMessage()), token));
        Exception safe;
        if (error instanceof HttpConnectTimeoutException) {
            safe = new HttpConnectTimeoutException(message);
        } else if (error instanceof HttpTimeoutException) {
            safe = new HttpTimeoutException(message);
        } else if (error instanceof InterruptedException) {
            safe = new InterruptedException(message);
        } else {
            safe = new IOException(message);
        }
        safe.setStackTrace(safeFrames(error.getStackTrace(), token));
        return safe;
    }

    /** Whether a {@link PayerCallException}'s own fields (body, kept headers, URI, payer) show {@code token}. */
    static boolean fieldsShow(PayerCallException failure, String token) {
        return shows(failure.responseBody(), token)
                || shows(failure.responseHeaders().map().toString(), token)
                || uriShows(failure.uri(), token)
                || shows(String.valueOf(failure.payerId()), token);
    }

    /** Whether {@code uri} shows {@code token}, as written or percent-decoded. */
    static boolean uriShows(URI uri, String token) {
        return uri != null && (shows(uri.toString(), token) || shows(String.valueOf(uri.getAuthority())
                + uri.getPath() + uri.getQuery() + uri.getFragment(), token));
    }

    /** {@code frames} with {@code token} removed from every class, method, file and module name. */
    static StackTraceElement[] safeFrames(StackTraceElement[] frames, String token) {
        if (token == null) {
            return frames;
        }
        StackTraceElement[] safe = frames.clone();
        for (int i = 0; i < safe.length; i++) {
            StackTraceElement f = safe[i];
            if (shows(f.toString(), token)) {
                safe[i] = new StackTraceElement(clean(f.getClassLoaderName(), token), clean(f.getModuleName(), token),
                        clean(f.getModuleVersion(), token), clean(f.getClassName(), token),
                        clean(f.getMethodName(), token), clean(f.getFileName(), token), f.getLineNumber());
            }
        }
        return safe;
    }

    /** {@code text} with {@code token} removed; the whole text becomes the marker if a spelling survives. */
    static String clean(String text, String token) {
        if (text == null) {
            return null;
        }
        String safe = redactToken(text, token);
        return shows(safe, token) ? MARKER : safe;
    }

    static boolean mentions(Throwable error, String token) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<Throwable> todo = new ArrayDeque<>(List.of(error));
        while (!todo.isEmpty()) {
            Throwable t = todo.pop();
            if (!seen.add(t)) {
                continue;
            }
            if (shows(String.valueOf(t.getMessage()), token) || shows(t.toString(), token)) {
                return true;
            }
            for (StackTraceElement frame : t.getStackTrace()) {
                if (shows(frame.toString(), token)) {
                    return true;
                }
            }
            if (t instanceof PayerCallException failure && fieldsShow(failure, token)) {
                return true;
            }
            if (t.getCause() != null) {
                todo.push(t.getCause());
            }
            todo.addAll(List.of(t.getSuppressed()));
        }
        return false;
    }

    /** Whether {@code text} shows {@code token} as is or once its JSON escapes are decoded. */
    static boolean shows(String text, String token) {
        return text.contains(token) || looselyDecoded(text).contains(token);
    }

    /** {@code text} with JSON string escapes decoded wherever they appear; unknown escapes are kept. */
    static String looselyDecoded(String text) {
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c != '\\' || i + 1 == text.length()) {
                out.append(c);
                continue;
            }
            char next = text.charAt(i + 1);
            int simple = "\"\\/bfnrt".indexOf(next);
            if (simple >= 0) {
                out.append("\"\\/\b\f\n\r\t".charAt(simple));
                i++;
            } else if (next == 'u' && i + 6 <= text.length() && isHex(text, i + 2, i + 6)) {
                out.append((char) Integer.parseInt(text.substring(i + 2, i + 6), 16));
                i += 5;
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static boolean isHex(String text, int from, int to) {
        for (int i = from; i < to; i++) {
            if (Character.digit(text.charAt(i), 16) < 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * {@code text} with {@code token} removed: as is, as Jackson escapes it inside a JSON string, and that
     * escaped form with {@code /} written as {@code \/}. Longest first, so the raw token never consumes
     * only the start of an escaped spelling (a token ending in a backslash, say) and leaves a stray tail.
     */
    static String redactToken(String text, String token) {
        String quoted = MAPPER.getNodeFactory().textNode(token).toString();
        String escaped = quoted.substring(1, quoted.length() - 1);
        String[] spellings = new LinkedHashSet<>(List.of(escaped.replace("/", "\\/"), escaped, token))
                .stream().sorted(Comparator.comparingInt(String::length).reversed()).toArray(String[]::new);
        return redact(text, spellings);
    }

    static String safeBody(PayerCallPhase phase, String body, String token) {
        if (phase != PayerCallPhase.TOKEN) {
            // A payer that echoes the EHR token back must not leak it into the listener either.
            return redactResponse(body, token);
        }
        return redactResponse(tokenSummary(body), token);
    }

    /** A TOKEN response reduced to its scalar {@code token_type}, {@code expires_in} and {@code scope}. */
    private static String tokenSummary(String body) {
        var safe = MAPPER.createObjectNode();
        try {
            JsonNode json = MAPPER.readTree(body);
            for (String field : List.of("token_type", "expires_in", "scope")) {
                if (json != null && json.has(field) && json.get(field).isValueNode()) {
                    safe.set(field, json.get(field));
                }
            }
        } catch (IOException ignored) {
            // Never expose raw token responses or parser exceptions containing their source.
        }
        return safe.toString();
    }
}
