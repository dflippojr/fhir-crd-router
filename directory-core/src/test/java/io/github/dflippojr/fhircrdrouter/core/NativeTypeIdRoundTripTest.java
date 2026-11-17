package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * #231: a newer version can write a field this version does not know with a native YAML type id (a polymorphic
 * {@code @JsonTypeInfo} property: {@code futurePolicy: !<limit>}). This version keeps the entry as invalid, but
 * its writer cannot keep the type id, and a newer reader cannot read the field without it. So an older writer's
 * save or delete refuses while such an entry would be rewritten, and the newer reader still reads the file.
 */
class NativeTypeIdRoundTripTest {

    /** A newer version's model: polymorphic fields whose type id YAML carries natively, as a tag. */
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
    @JsonSubTypes(@JsonSubTypes.Type(value = Limit.class, name = "limit"))
    interface Policy { }

    record Limit(int count) implements Policy { }

    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
    @JsonSubTypes(@JsonSubTypes.Type(value = Steps.class, name = "steps"))
    interface Plan { }

    @JsonFormat(shape = JsonFormat.Shape.ARRAY)
    @JsonPropertyOrder({"first", "second"})
    record Steps(int first, int second) implements Plan { }

    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
    @JsonSubTypes(@JsonSubTypes.Type(value = Code.class, name = "code"))
    interface Ref { }

    record Code(@JsonValue String value) implements Ref {
        @JsonCreator
        Code { }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record NewerConnection(String payerId, Policy futurePolicy, Plan futurePlan, Ref futureRef) { }

    private static final ObjectMapper NEWER = new ObjectMapper(new YAMLFactory());

    private static final String OK_ENTRY = InvalidEntryIsolationTest.OK_ENTRY;

    private static String newerEntry(String field) {
        return """
                - payerId: "PAYER-NEWER"
                  environment: "PRODUCTION"
                  baseUrl: "https://newer.example/r4"
                  authType: "NONE"
                """ + field;
    }

    /** The tags below are what the newer writer itself emits for a mapping and a sequence. */
    @Test
    void theNewerWriterTagsAMappingAndASequence() throws Exception {
        String written = NEWER.writeValueAsString(new NewerConnection("P", new Limit(2), new Steps(1, 2), null));

        assertTrue(written.contains("futurePolicy: !<limit>\n  count: 2"), written);
        assertTrue(written.contains("futurePlan: !<steps>\n- 1\n- 2"), written);
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', value = {
            "tagged mapping  | '  futurePolicy: !<limit>\n    count: 2\n'          | futurePolicy",
            "tagged sequence | '  futurePlan: !<steps>\n  - 1\n  - 2\n'            | futurePlan",
            "tagged string   | '  futureRef: !<code> abc\n'                        | futureRef",
            "nested tag      | '  futureList:\n  - {futurePolicy: !<limit> {count: 2}}\n' | futureList[0].futurePolicy",
    })
    void anOlderWriterRefusesAndTheNewerReaderStillReadsTheFile(String name, String field, String path,
                                                                @TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, newerEntry(field.replace("\\n", "\n")) + OK_ENTRY);
        byte[] bytes = Files.readAllBytes(file);
        NewerConnection[] before = NEWER.readValue(bytes, NewerConnection[].class);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);
        assertEquals(List.of("PAYER-OK"), store.findAll().stream().map(ConnectionRecord::payerId).toList());

        RouterException onSave = assertThrows(RouterException.class, () -> store.save(ConnectionRecord.builder()
                .payerId("PAYER-NEW").environment(Environment.SANDBOX).baseUrl("https://new.example/r4")
                .authType(AuthType.NONE).build()));
        RouterException onDelete = assertThrows(RouterException.class,
                () -> store.delete("PAYER-OK", Environment.PRODUCTION));

        for (RouterException e : List.of(onSave, onDelete)) {
            assertTrue(e.getMessage().contains("entry 0 (payerId=PAYER-NEWER environment=PRODUCTION), field " + path),
                    e.getMessage());
        }
        assertArrayEquals(bytes, Files.readAllBytes(file));
        assertEquals(List.of(before), List.of(NEWER.readValue(Files.readAllBytes(file), NewerConnection[].class)));
    }

    /**
     * YAML's own standard tags (!!map, !!seq, !!str) are not type ids, but they are explicit tags, which the
     * rewrite cannot keep either: only a plain tree is written back (#231, owner decision: allowlist).
     */
    @Test
    void standardTagsRefuseToo(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, newerEntry("  futureMap: !!map {a: 1}\n  futureSeq: !!seq [1]\n  futureText: !!str x\n")
                + OK_ENTRY);
        byte[] bytes = Files.readAllBytes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        RouterException e = assertThrows(RouterException.class, () -> store.delete("PAYER-OK", Environment.PRODUCTION));

        for (String field : List.of("futureMap", "futureSeq", "futureText")) {
            assertTrue(e.getMessage().contains("entry 0 (payerId=PAYER-NEWER environment=PRODUCTION), field " + field),
                    e.getMessage());
        }
        assertArrayEquals(bytes, Files.readAllBytes(file));
        assertEquals(1, new FileBasedConnectionStore(file).invalidEntries().size());
    }

    /**
     * An entry tagged as a whole still binds (the record has no polymorphic type), but a rewrite cannot keep its
     * tag: a save of another payer, and a save over the entry itself, both refuse and name the entry.
     */
    @Test
    void anEntryTaggedAsAWholeRefusesEveryRewriteOfIt(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - !<newer>
                  payerId: "PAYER-T"
                  environment: "PRODUCTION"
                  baseUrl: "https://t.example/r4"
                  authType: "NONE"
                """ + OK_ENTRY);
        byte[] bytes = Files.readAllBytes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);
        assertEquals("https://t.example/r4", new PayerRouter(store).resolve("PAYER-T").baseUrl());

        RouterException onOther = assertThrows(RouterException.class, () -> store.save(ConnectionRecord.builder()
                .payerId("PAYER-NEW").environment(Environment.SANDBOX).baseUrl("https://new.example/r4")
                .authType(AuthType.NONE).build()));
        RouterException onItself = assertThrows(RouterException.class, () -> store.save(ConnectionRecord.builder()
                .payerId("PAYER-T").environment(Environment.PRODUCTION).baseUrl("https://t2.example/r4")
                .authType(AuthType.NONE).build()));

        for (RouterException e : List.of(onOther, onItself)) {
            assertTrue(e.getMessage().contains("entry 0 (payerId=PAYER-T environment=PRODUCTION), the entry itself"),
                    e.getMessage());
        }
        assertArrayEquals(bytes, Files.readAllBytes(file));
    }

    /** Deleting the entry that holds the type id is still allowed: nothing of it is rewritten. */
    @Test
    void theEntryWithATypeIdCanStillBeDeleted(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, newerEntry("  futurePolicy: !<limit>\n    count: 2\n") + OK_ENTRY);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        store.delete("PAYER-NEWER", Environment.PRODUCTION);

        assertEquals(List.of(), new FileBasedConnectionStore(file).invalidEntries());
    }
}
