package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * #231, owner decision after migration review 3: a rewrite may write an untouched entry back only if its parsed
 * tree is plain, made of mappings, sequences and scalars with no anchor, alias, tag or duplicate key. Any other
 * entry is refused by name and the file is left as it was; one test per construct.
 */
class PlainTreeAllowlistTest {

    /** A newer version's rule, shared by identity: its writer emits the second use as a YAML alias. */
    @JsonIdentityInfo(generator = ObjectIdGenerators.IntSequenceGenerator.class, property = "@id")
    public static final class Rule {
        public int count;

        public Rule() {
        }

        Rule(int count) {
            this.count = count;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonPropertyOrder({"payerId", "environment", "baseUrl", "authType", "futureRules"})
    public static final class NewerConnection {
        public String payerId;
        public String environment;
        public String baseUrl;
        public String authType;
        public List<Rule> futureRules;
    }

    private static final ObjectMapper NEWER = new ObjectMapper(new YAMLFactory());

    private static final String OK_ENTRY = InvalidEntryIsolationTest.OK_ENTRY;

    private static ConnectionRecord.Builder recordFor(String payerId) {
        return ConnectionRecord.builder().payerId(payerId).environment(Environment.PRODUCTION)
                .baseUrl("https://" + payerId.toLowerCase() + ".example/r4").authType(AuthType.NONE);
    }

    private static ConnectionRecord other() {
        return ConnectionRecord.builder().payerId("PAYER-NEW").environment(Environment.SANDBOX)
                .baseUrl("https://new.example/r4").authType(AuthType.NONE).build();
    }

    /** Runs the write, which must refuse with a message holding every part, and leave the bytes unchanged. */
    private static void assertRefuses(Path file, Consumer<FileBasedConnectionStore> write, String... parts)
            throws Exception {
        byte[] bytes = Files.readAllBytes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);
        RouterException e = assertThrows(RouterException.class, () -> write.accept(store));
        for (String part : parts) {
            assertTrue(e.getMessage().contains(part), e.getMessage());
        }
        assertArrayEquals(bytes, Files.readAllBytes(file));
    }

    /**
     * A newer writer's shared object ({@code @JsonIdentityInfo}) is an anchor and an alias. A rewrite would drop
     * the anchor and write the alias as the string "1", and the newer reader could no longer resolve it. An
     * unrelated save and delete refuse, and the newer reader still reads one shared rule.
     */
    @Test
    void anIdentitySharedObjectRefusesAnUnrelatedSaveAndDelete(@TempDir Path dir) throws Exception {
        NewerConnection newer = new NewerConnection();
        newer.payerId = "PAYER-NEWER";
        newer.environment = "PRODUCTION";
        newer.baseUrl = "https://newer.example/r4";
        newer.authType = "NONE";
        Rule shared = new Rule(2);
        newer.futureRules = List.of(shared, shared);
        String written = NEWER.writeValueAsString(List.of(newer));
        assertTrue(written.contains("- &1 count: 2\n  - *1\n"), written);
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, written + OK_ENTRY);
        assertEquals(List.of("PAYER-OK"),
                new FileBasedConnectionStore(file).findAll().stream().map(ConnectionRecord::payerId).toList());

        String entry = "entry 0 (payerId=PAYER-NEWER environment=PRODUCTION), field futureRules";
        assertRefuses(file, store -> store.save(other()), entry + "[0]", entry + "[1] (a YAML alias)");
        assertRefuses(file, store -> store.delete("PAYER-OK", Environment.PRODUCTION),
                entry + "[0]", entry + "[1] (a YAML alias)");

        NewerConnection read = NEWER.readValue(Files.readAllBytes(file), NewerConnection[].class)[0];
        assertSame(read.futureRules.get(0), read.futureRules.get(1));
        assertEquals(2, read.futureRules.get(0).count);
    }

    /**
     * A scalar anchor in one entry and its alias in another: deleting the anchor's entry would leave the alias
     * unresolved, so it refuses; so do an unrelated save and deleting the alias's entry, which would drop the
     * anchor. The bytes are unchanged and both entries read as before.
     */
    @Test
    void aScalarAliasAcrossEntriesRefusesEveryRewrite(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: "PAYER-A"
                  environment: "PRODUCTION"
                  baseUrl: "https://a.example/r4"
                  authType: "NONE"
                  futureShared: &shared "x"
                - payerId: "PAYER-B"
                  environment: "PRODUCTION"
                  baseUrl: "https://b.example/r4"
                  authType: "NONE"
                  futureShared: *shared
                """ + OK_ENTRY);
        String anchor = "entry 0 (payerId=PAYER-A environment=PRODUCTION), field futureShared (a YAML anchor)";
        String alias = "entry 1 (payerId=PAYER-B environment=PRODUCTION), field futureShared (a YAML alias)";

        assertRefuses(file, store -> store.delete("PAYER-A", Environment.PRODUCTION), alias);
        assertRefuses(file, store -> store.delete("PAYER-B", Environment.PRODUCTION), anchor);
        assertRefuses(file, store -> store.save(other()), anchor, alias);
        assertEquals(2, new FileBasedConnectionStore(file).invalidEntries().size());
    }

    /** An anchor on a known field of a readable entry refuses an unrelated save; a save that sets the field repairs it. */
    @Test
    void anAnchorOnAKnownFieldRefusesUntilTheSaveSetsTheField(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: "PAYER-A"
                  environment: "PRODUCTION"
                  baseUrl: &url "https://a.example/r4"
                  authType: "NONE"
                """);

        assertRefuses(file, store -> store.save(other()),
                "entry 0 (payerId=PAYER-A environment=PRODUCTION), field baseUrl (a YAML anchor)");

        new FileBasedConnectionStore(file).save(recordFor("PAYER-A").baseUrl("https://a2.example/r4").build());
        assertEquals("https://a2.example/r4", new FileBasedConnectionStore(file).findAll().get(0).baseUrl());
    }

    /** YAML's own tags, which agree with their values, are explicit tags too: the rewrite cannot keep them. */
    @Test
    void anExplicitStandardTagRefuses(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: "PAYER-T"
                  environment: "PRODUCTION"
                  baseUrl: "https://t.example/r4"
                  authType: "NONE"
                  futureText: !!str x
                  futureInt: !!int 7
                  futureMap: !!map {a: 1}
                  futureSeq: !!seq [1]
                """ + OK_ENTRY);
        String entry = "entry 0 (payerId=PAYER-T environment=PRODUCTION), field ";

        assertRefuses(file, store -> store.delete("PAYER-OK", Environment.PRODUCTION),
                entry + "futureText (a YAML tag)", entry + "futureInt (a YAML tag)",
                entry + "futureMap (a YAML tag)", entry + "futureSeq (a YAML tag)");
    }

    /**
     * A tag or anchor on a mapping key, the first key included, is outside the plain tree too. Jackson's parser
     * does not report a tag on a key at all, which is why the allowlist reads the YAML events themselves.
     */
    @Test
    void aTagOrAnchorOnAKeyRefuses(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - &k payerId: "PAYER-K"
                  environment: "PRODUCTION"
                  baseUrl: "https://k.example/r4"
                  authType: "NONE"
                - !!str payerId: "PAYER-T"
                  environment: "PRODUCTION"
                  baseUrl: "https://t.example/r4"
                  authType: "NONE"
                  !!str futureKey: 1
                """ + OK_ENTRY);

        assertRefuses(file, store -> store.save(other()),
                "entry 0 (payerId=PAYER-K environment=PRODUCTION), field payerId (a YAML anchor on its key)",
                "entry 1 (payerId=PAYER-T environment=PRODUCTION), field payerId (a YAML tag on its key)",
                "entry 1 (payerId=PAYER-T environment=PRODUCTION), field futureKey (a YAML tag on its key)");
    }

    /** A second YAML document is never read, and a rewrite would drop it: writes refuse; reads go on. */
    @Test
    void aSecondDocumentRefusesAWrite(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, OK_ENTRY + "---\n- payerId: \"PAYER-2\"\n");

        assertRefuses(file, store -> store.save(other()), "the document itself (a second YAML document)");
        assertEquals(List.of("PAYER-OK"),
                new FileBasedConnectionStore(file).findAll().stream().map(ConnectionRecord::payerId).toList());
    }

    /** A tag or anchor on the list itself belongs to no entry: writes refuse at document level; reads go on. */
    @Test
    void aTagOnTheListItselfRefusesAWrite(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, "--- !!seq\n" + OK_ENTRY);

        assertRefuses(file, store -> store.delete("PAYER-OK", Environment.PRODUCTION),
                "the document itself (a YAML tag)");
        assertEquals(1, new FileBasedConnectionStore(file).findAll().size());
    }
}
