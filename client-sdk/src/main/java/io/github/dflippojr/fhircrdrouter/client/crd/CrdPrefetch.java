package io.github.dflippojr.fhircrdrouter.client.crd;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Builds a CDS Hooks {@code prefetch} map using the keys CRD defines, e.g.
 * {@code "patient": Patient/{{context.patientId}}} and
 * {@code "coverage": Coverage?patient={{context.patientId}}&status=active}.
 *
 * <p>Payers advertise the prefetch templates they actually want in their
 * discovery response ({@code CdsServiceDescriptor#prefetch()}); anything they
 * ask for that isn't a well-known key can be added with {@link Builder#put}.
 */
public final class CrdPrefetch {

    public static final String PATIENT = "patient";
    public static final String ENCOUNTER = "encounter";
    /** A searchset Bundle of the patient's active Coverage resources. */
    public static final String COVERAGE = "coverage";

    private CrdPrefetch() { }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final Map<String, Object> entries = new LinkedHashMap<>();

        public Builder patient(JsonNode patient) { return put(PATIENT, patient); }
        public Builder encounter(JsonNode encounter) { return put(ENCOUNTER, encounter); }
        public Builder coverage(JsonNode coverageBundle) { return put(COVERAGE, coverageBundle); }

        public Builder put(String key, JsonNode resource) {
            entries.put(Objects.requireNonNull(key, "key"), Objects.requireNonNull(resource, key));
            return this;
        }

        public Map<String, Object> build() {
            return Collections.unmodifiableMap(new LinkedHashMap<>(entries));
        }
    }
}
