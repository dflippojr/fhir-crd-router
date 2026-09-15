package io.github.dflippojr.fhircrdrouter.client.crd;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

/**
 * Typed {@code context} objects for the CDS hooks Da Vinci CRD supports,
 * following the CRD 2.2.1 logical models (e.g. {@code CRDOrderSignContext}).
 *
 * <p>FHIR resources ({@code draftOrders}, {@code appointments}, tasks) stay
 * as Jackson {@link JsonNode}s rather than pulling in HAPI FHIR, which keeps
 * this library dependency-light. Construction validates the required
 * elements and basic shapes, not full FHIR profile conformance.
 */
public sealed interface CrdHookContext {

    /** The CDS Hooks hook name this context belongs to, e.g. {@code order-sign}. */
    @JsonIgnore
    String hook();

    /** {@code order-sign}: orders about to be signed. CRD primary hook. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    record OrderSign(String userId, String patientId, String encounterId, JsonNode draftOrders)
            implements CrdHookContext {
        public OrderSign {
            Checks.userId(userId);
            Checks.required(patientId, "patientId");
            Checks.bundle(draftOrders, "draftOrders");
        }

        @Override public String hook() { return "order-sign"; }
    }

    /** {@code order-select}: orders just selected, with the rest of the draft order set. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    record OrderSelect(String userId, String patientId, String encounterId, List<String> selections,
                       JsonNode draftOrders) implements CrdHookContext {
        public OrderSelect {
            Checks.userId(userId);
            Checks.required(patientId, "patientId");
            selections = selections == null ? List.of() : List.copyOf(selections);
            selections.forEach(s -> Checks.localReference(s, "selections"));
            Checks.bundle(draftOrders, "draftOrders");
        }

        @Override public String hook() { return "order-select"; }
    }

    /** {@code order-dispatch}: signed orders being sent to a performer. CRD primary hook. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    record OrderDispatch(String patientId, List<String> dispatchedOrders, String performer,
                         List<JsonNode> fulfillmentTasks) implements CrdHookContext {
        public OrderDispatch {
            Checks.required(patientId, "patientId");
            if (dispatchedOrders == null || dispatchedOrders.isEmpty()) {
                throw new IllegalArgumentException("dispatchedOrders requires at least one reference");
            }
            dispatchedOrders = List.copyOf(dispatchedOrders);
            dispatchedOrders.forEach(s -> Checks.localReference(s, "dispatchedOrders"));
            if (performer != null) {
                Checks.localReference(performer, "performer");
            }
            fulfillmentTasks = fulfillmentTasks == null || fulfillmentTasks.isEmpty() ? null : List.copyOf(fulfillmentTasks);
        }

        @Override public String hook() { return "order-dispatch"; }
    }

    /** {@code appointment-book}: appointments about to be booked. CRD primary hook. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    record AppointmentBook(String userId, String patientId, String encounterId, JsonNode appointments)
            implements CrdHookContext {
        public AppointmentBook {
            Checks.userId(userId);
            Checks.required(patientId, "patientId");
            Checks.bundle(appointments, "appointments");
        }

        @Override public String hook() { return "appointment-book"; }
    }

    /** {@code encounter-start}: a patient encounter is beginning. */
    record EncounterStart(String userId, String patientId, String encounterId) implements CrdHookContext {
        public EncounterStart {
            Checks.userId(userId);
            Checks.required(patientId, "patientId");
            Checks.required(encounterId, "encounterId");
        }

        @Override public String hook() { return "encounter-start"; }
    }

    /** {@code encounter-discharge}: a patient is being discharged. */
    record EncounterDischarge(String userId, String patientId, String encounterId) implements CrdHookContext {
        public EncounterDischarge {
            Checks.userId(userId);
            Checks.required(patientId, "patientId");
            Checks.required(encounterId, "encounterId");
        }

        @Override public String hook() { return "encounter-discharge"; }
    }
}
