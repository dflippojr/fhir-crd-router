package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.dflippojr.fhircrdrouter.client.crd.CoverageInformation;

import java.util.ArrayList;
import java.util.List;

/**
 * A CDS Hooks call's response, exposed two ways per the capsule's "optional
 * client SDK" decision: {@link #cards()} and {@link #systemActions()} for the
 * common typed case, and {@link #rawJson()} as an escape hatch passthrough for
 * anything the typed models don't capture.
 */
public record CdsHookResponse(List<Card> cards, List<SystemAction> systemActions, JsonNode rawJson) {

    public CdsHookResponse {
        cards = List.copyOf(cards);
        systemActions = List.copyOf(systemActions);
    }

    /**
     * All CRD coverage determinations the payer returned. CRD 2.x delivers
     * these as {@code systemActions}, but some payers (including the HL7 CRD
     * reference implementation) put them in card suggestion actions, so both
     * places are searched.
     */
    public List<CoverageInformation> coverageInformation() {
        List<CoverageInformation> result = new ArrayList<>();
        for (JsonNode action : rawJson.path("systemActions")) {
            result.addAll(CoverageInformation.fromResource(action.get("resource")));
        }
        for (JsonNode card : rawJson.path("cards")) {
            for (JsonNode suggestion : card.path("suggestions")) {
                for (JsonNode action : suggestion.path("actions")) {
                    result.addAll(CoverageInformation.fromResource(action.get("resource")));
                }
            }
        }
        return result;
    }
}
