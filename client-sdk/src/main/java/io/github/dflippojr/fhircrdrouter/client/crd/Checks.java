package io.github.dflippojr.fhircrdrouter.client.crd;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Objects;
import java.util.regex.Pattern;

/** Shape checks shared by the {@link CrdHookContext} records. */
final class Checks {
    private static final Pattern LOCAL_REFERENCE = Pattern.compile("[A-Z][A-Za-z]+/[A-Za-z0-9\\-.]{1,64}");

    private Checks() { }

    static void required(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " is required");
        }
    }

    static void userId(String userId) {
        required(userId, "userId");
        localReference(userId, "userId");
    }

    static void localReference(String value, String name) {
        if (value == null || !LOCAL_REFERENCE.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " must be a [ResourceType]/[id] reference, got: " + value);
        }
    }

    static void bundle(JsonNode node, String name) {
        Objects.requireNonNull(node, name);
        if (!"Bundle".equals(node.path("resourceType").asText())) {
            throw new IllegalArgumentException(name + " must be a FHIR Bundle");
        }
    }
}
