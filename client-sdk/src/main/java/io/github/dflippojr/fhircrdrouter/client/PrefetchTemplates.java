package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Expands a payer's discovery {@code prefetch} templates into FHIR query
 * strings for one hook request, following
 * <a href="https://cds-hooks.hl7.org/2.0/#prefetch-tokens">CDS Hooks 2.0 prefetch tokens</a>.
 *
 * <p>Supported tokens are root-level primitive {@code context} fields
 * ({@code {{context.patientId}}}) and the four user tokens
 * ({@code {{userPractitionerId}}}, {@code {{userPractitionerRoleId}}},
 * {@code {{userPatientId}}}, {@code {{userRelatedPersonId}}}), derived from
 * {@code context.userId}. Any key that cannot be fully expanded is reported in
 * {@link Expansion#unresolved()}; the spec says a client MUST NOT send a
 * prefetch key it does not satisfy. This does not run the queries.
 */
public final class PrefetchTemplates {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern FHIR_ID = Pattern.compile("[A-Za-z0-9\\-.]{1,64}");
    private static final Pattern FIELD_NAME = Pattern.compile("[A-Za-z_]\\w*");
    private static final String CONTEXT_PREFIX = "context.";
    private static final Map<String, String> USER_TOKENS = Map.of(
            "userPractitionerId", "Practitioner",
            "userPractitionerRoleId", "PractitionerRole",
            "userPatientId", "Patient",
            "userRelatedPersonId", "RelatedPerson");

    private PrefetchTemplates() { }

    /**
     * The result of {@link #expand}. Both maps are immutable and keep the
     * input template key order; every input key appears in exactly one of them.
     *
     * @param queries key to expanded FHIR query, e.g. {@code Coverage?patient=pat-1&status=active}
     * @param unresolved key to a short reason, e.g. {@code context.encounterId is absent}.
     *     Reasons name fields, never their values.
     */
    public record Expansion(Map<String, String> queries, Map<String, String> unresolved) {
        public Expansion {
            queries = Collections.unmodifiableMap(new LinkedHashMap<>(queries));
            unresolved = Collections.unmodifiableMap(new LinkedHashMap<>(unresolved));
        }
    }

    /**
     * Expands each template against {@code request.context()} (a
     * {@code CrdHookContext} record or a {@code Map}). Values matching the FHIR
     * id pattern are inserted as is; anything else is percent-encoded (UTF-8)
     * so it cannot add query parameters. Never throws for template content.
     *
     * @throws NullPointerException if {@code templates}, {@code request} or a template key is null
     */
    public static Expansion expand(Map<String, String> templates, CdsHookRequest request) {
        Objects.requireNonNull(templates, "templates");
        Objects.requireNonNull(request, "request");
        JsonNode context = MAPPER.valueToTree(request.context());
        Map<String, String> queries = new LinkedHashMap<>();
        Map<String, String> unresolved = new LinkedHashMap<>();
        templates.forEach((key, template) -> {
            Objects.requireNonNull(key, "template key");
            Result result = template == null ? Result.failed("template is null") : expandOne(template, context);
            if (result.reason == null) {
                queries.put(key, result.value);
            } else {
                unresolved.put(key, result.reason);
            }
        });
        return new Expansion(queries, unresolved);
    }

    private static Result expandOne(String template, JsonNode context) {
        StringBuilder out = new StringBuilder(template.length());
        int pos = 0;
        while (true) {
            int open = template.indexOf("{{", pos);
            if (open < 0) {
                out.append(template, pos, template.length());
                return Result.ok(out.toString());
            }
            int close = template.indexOf("}}", open + 2);
            if (close < 0) {
                return Result.failed("unterminated {{");
            }
            Result token = resolve(template.substring(open + 2, close).trim(), context);
            if (token.reason != null) {
                return token;
            }
            out.append(template, pos, open).append(encode(token.value));
            pos = close + 2;
        }
    }

    private static Result resolve(String token, JsonNode context) {
        String resourceType = USER_TOKENS.get(token);
        if (resourceType != null) {
            return userToken(token, resourceType, context);
        }
        if (token.startsWith(CONTEXT_PREFIX)) {
            String field = token.substring(CONTEXT_PREFIX.length());
            if (FIELD_NAME.matcher(field).matches()) {
                return contextField(field, context);
            }
            if (field.contains(".") && FIELD_NAME.matcher(field.substring(0, field.indexOf('.'))).matches()) {
                return Result.failed("{{" + token + "}} is a nested path; only root-level context fields are supported");
            }
        }
        return Result.failed("unsupported token {{" + token + "}}");
    }

    private static Result contextField(String field, JsonNode context) {
        JsonNode value = context.isObject() ? context.get(field) : null;
        String name = CONTEXT_PREFIX + field;
        if (value == null || value.isNull()) {
            return Result.failed(name + " is absent");
        }
        if (!value.isTextual() && !value.isNumber() && !value.isBoolean()) {
            return Result.failed(name + " is not a primitive");
        }
        return Result.ok(value.asText());
    }

    private static Result userToken(String token, String resourceType, JsonNode context) {
        Result userId = contextField("userId", context);
        if (userId.reason != null) {
            return userId;
        }
        String prefix = resourceType + "/";
        String reference = userId.value;
        if (!reference.startsWith(prefix) || reference.length() == prefix.length()) {
            return Result.failed("{{" + token + "}} needs context.userId to be a " + resourceType + " reference");
        }
        return Result.ok(reference.substring(prefix.length()));
    }

    private static String encode(String value) {
        if (FHIR_ID.matcher(value).matches()) {
            return value;
        }
        // URLEncoder is form encoding; a literal '+' is already %2B, so '+' here is always a space.
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /** Either an expanded value or the reason expansion failed. */
    private record Result(String value, String reason) {
        static Result ok(String value) { return new Result(value, null); }
        static Result failed(String reason) { return new Result(null, reason); }
    }
}
