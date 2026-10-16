package io.github.dflippojr.fhircrdrouter.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** Deliberately failing test to show the CI gate turns red. Never merge. */
class GateRedDemoTest {

    @Test
    void failsOnPurpose() {
        assertEquals(1, 2, "deliberate failure for #93 gate proof");
    }
}
