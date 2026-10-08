package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Offline, opt-in shape checks for a
 * <a href="https://cds-hooks.hl7.org/2.0/#discovery">CDS Hooks 2.0 discovery catalog</a>.
 * Checks the root, services array, required nonblank id/hook/description strings,
 * optional textual title and optional prefetch object with nonblank string values.
 * Nonblank checks follow this SDK's diagnostic convention. Unknown properties,
 * custom hooks, payer-specific keys and repeated IDs are allowed. This does not
 * execute queries, expand templates or perform full FHIR validation.
 */
public final class CdsDiscoveryValidator {
    /** Severity of a catalog finding. */
    public enum Severity { ERROR }

    /** One finding, with a location such as {@code services[0].id}. */
    public record Violation(Severity severity, String path, String message) {
        public Violation {
            Objects.requireNonNull(severity, "severity");
            Objects.requireNonNull(path, "path");
            Objects.requireNonNull(message, "message");
        }
    }

    private CdsDiscoveryValidator() { }

    /**
     * Returns immutable findings in service order; checks id, hook, description,
     * title, then prefetch (keys in input order). Malformed parents have no child findings.
     * Java null and malformed JSON tree shapes are accepted and reported.
     */
    public static List<Violation> validate(JsonNode catalog) {
        if (catalog == null || !catalog.isObject()) {
            return List.of(error("$", "Discovery response must be an object"));
        }
        JsonNode services = catalog.get("services");
        if (services == null || !services.isArray()) {
            return List.of(error("services", "services is required and must be an array"));
        }
        List<Violation> findings = new ArrayList<>();
        for (int i = 0; i < services.size(); i++) {
            String path = "services[" + i + "]";
            JsonNode service = services.get(i);
            if (!service.isObject()) {
                findings.add(error(path, "Service entry must be an object"));
            } else {
                validateService(service, path, findings);
            }
        }
        return List.copyOf(findings);
    }

    private static void validateService(JsonNode service, String path, List<Violation> findings) {
        for (String field : List.of("id", "hook", "description")) {
            if (!nonblankText(service.get(field))) {
                findings.add(error(path + "." + field, field + " is required and must be a nonblank string"));
            }
        }
        JsonNode title = service.get("title");
        if (title != null && !title.isTextual()) {
            findings.add(error(path + ".title", "title must be a string when present"));
        }
        JsonNode prefetch = service.get("prefetch");
        if (prefetch != null) {
            validatePrefetch(prefetch, path + ".prefetch", findings);
        }
    }

    private static void validatePrefetch(JsonNode prefetch, String path, List<Violation> findings) {
        if (!prefetch.isObject()) {
            findings.add(error(path, "prefetch must be an object when present"));
            return;
        }
        prefetch.fields().forEachRemaining(entry -> {
            if (!nonblankText(entry.getValue())) {
                findings.add(error(path + "." + entry.getKey(), "Prefetch template must be a nonblank string"));
            }
        });
    }

    private static boolean nonblankText(JsonNode value) {
        return value != null && value.isTextual() && !value.textValue().isBlank();
    }

    private static Violation error(String path, String message) {
        return new Violation(Severity.ERROR, path, message);
    }
}
