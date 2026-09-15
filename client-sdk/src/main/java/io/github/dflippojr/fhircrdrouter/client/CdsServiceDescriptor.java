package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * One entry from a payer's standard {@code GET {baseUrl}/cds-services}
 * discovery response. The router does not maintain its own duplicate
 * catalog — this is fetched live from the payer.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CdsServiceDescriptor(
        String hook,
        String title,
        String description,
        String id
) {
}
