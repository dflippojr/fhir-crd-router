package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.Map;

/**
 * One entry from a payer's standard {@code GET {baseUrl}/cds-services}
 * discovery response. The router does not maintain its own duplicate
 * catalog — this is fetched live from the payer.
 *
 * @param prefetch the payer's prefetch templates (key to FHIR query), e.g.
 *     {@code "coverage": "Coverage?patient={{context.patientId}}&status=active"}
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
        prefetch = prefetch == null ? Map.of() : Map.copyOf(prefetch);
    }
}
