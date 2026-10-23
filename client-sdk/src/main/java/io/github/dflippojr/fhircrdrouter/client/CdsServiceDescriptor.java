package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One entry from a payer's standard {@code GET {baseUrl}/cds-services}
 * discovery response. The router does not maintain its own duplicate
 * catalog — this is fetched live from the payer.
 *
 * @param prefetch the payer's prefetch templates (key to FHIR query), e.g.
 *     {@code "coverage": "Coverage?patient={{context.patientId}}&status=active"},
 *     in the payer's order. A value is null when the payer sent an invalid
 *     {@code null} template: {@link PrefetchTemplates#expand} reports that key as
 *     unresolved and {@link CdsDiscoveryValidator} flags it
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CdsServiceDescriptor(
        String hook,
        String title,
        String description,
        String id,
        Map<String, String> prefetch
) {
    public CdsServiceDescriptor {
        if (prefetch == null) {
            prefetch = Map.of();
        } else {
            // Not Map.copyOf: one payer's null template must not fail the whole catalog (#107),
            // as CdsHookRequest keeps null prefetch values (#66); null keys stay invalid.
            Map<String, String> copy = new LinkedHashMap<>(prefetch);
            if (copy.containsKey(null)) {
                throw new NullPointerException("prefetch key");
            }
            prefetch = Collections.unmodifiableMap(copy);
        }
    }
}
