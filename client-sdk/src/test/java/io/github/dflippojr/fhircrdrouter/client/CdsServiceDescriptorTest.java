package io.github.dflippojr.fhircrdrouter.client;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CdsServiceDescriptorTest {
    @Test
    void keepsNullTemplateValuesInOrderAsAnUnmodifiableCopy() {
        Map<String, String> templates = new LinkedHashMap<>();
        templates.put("z", "Patient/{{context.patientId}}");
        templates.put("k", null);
        CdsServiceDescriptor descriptor = new CdsServiceDescriptor("order-sign", null, "d", "id", templates);
        templates.put("later", "Coverage");

        assertEquals(List.of("z", "k"), List.copyOf(descriptor.prefetch().keySet()));
        assertTrue(descriptor.prefetch().containsKey("k"));
        assertNull(descriptor.prefetch().get("k"));
        assertThrows(UnsupportedOperationException.class, () -> descriptor.prefetch().remove("z"));
    }

    @Test
    void nullPrefetchBecomesEmpty() {
        assertEquals(Map.of(), new CdsServiceDescriptor("order-sign", null, "d", "id", null).prefetch());
    }

    @Test
    void nullTemplateKeyIsRejected() {
        Map<String, String> templates = new HashMap<>();
        templates.put(null, "Patient");
        NullPointerException e = assertThrows(NullPointerException.class,
                () -> new CdsServiceDescriptor("order-sign", null, "d", "id", templates));
        assertEquals("prefetch key", e.getMessage());
    }
}
