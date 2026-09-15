package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Map;

/**
 * Typed view of a CDS Hooks response Card, covering the commonly used
 * top-level fields. Use {@link CdsHookResponse#rawJson()} for anything this
 * doesn't cover (e.g. exotic suggestion/action shapes).
 *
 * <p>CRD requires {@code source.label} to name the insurer and
 * {@code source.topic} to say which CRD response type the card is.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Card(
        String uuid,
        String summary,
        String detail,
        String indicator,
        Source source,
        List<Map<String, Object>> suggestions,
        String selectionBehavior,
        List<Map<String, Object>> links
) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Source(String label, String url, String icon, Coding topic) { }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Coding(String system, String code, String display) { }
}
