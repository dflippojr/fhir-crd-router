package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

/**
 * A CDS Hooks call's response, exposed two ways per the capsule's "optional
 * client SDK" decision: {@link #cards()} for the common typed case, and
 * {@link #rawJson()} as an escape hatch passthrough for anything the typed
 * {@link Card} model doesn't capture.
 */
public record CdsHookResponse(List<Card> cards, JsonNode rawJson) {
}
