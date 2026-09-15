package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * A CDS Hooks {@code systemActions} entry: a change the service wants the
 * EHR to apply without user interaction. CRD delivers Coverage Information
 * this way, as an {@code update} to the order carrying the
 * {@code ext-coverage-information} extension (see {@link io.github.dflippojr.fhircrdrouter.client.crd.CoverageInformation}).
 *
 * @param type {@code create}, {@code update}, or {@code delete}
 * @param resource the FHIR resource to create or update, if any
 * @param resourceId for {@code delete}, the {@code [ResourceType]/[id]} to remove
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SystemAction(String type, String description, JsonNode resource, String resourceId) {
}
