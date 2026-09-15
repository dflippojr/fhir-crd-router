package io.github.dflippo.fhircrdrouter.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

/**
 * Typed view of a CDS Hooks response Card, covering the commonly used
 * top-level fields. Use {@link CdsHookResponse#rawJson()} for anything this
 * doesn't cover (e.g. exotic suggestion/action shapes).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Card(
        String summary,
        String detail,
        String indicator,
        Map<String, Object> source,
        List<Map<String, Object>> suggestions,
        List<Map<String, Object>> links
) {
}
