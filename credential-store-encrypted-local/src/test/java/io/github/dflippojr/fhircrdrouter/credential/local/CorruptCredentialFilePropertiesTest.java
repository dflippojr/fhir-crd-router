package io.github.dflippojr.fhircrdrouter.credential.local;

import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Tuple;
import net.jqwik.api.lifecycle.AfterContainer;
import net.jqwik.api.lifecycle.BeforeContainer;
import net.jqwik.api.lifecycle.BeforeTry;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Corrupt {@code key.bin} or {@code secrets.properties} contents give a documented error (an
 * {@link IllegalStateException} or {@link UncheckedIOException} that leaks no secret material),
 * never a {@link NegativeArraySizeException} or {@link IllegalArgumentException}, never a wrong
 * secret and never a silently replaced key (the #65 class), including a {@code secrets.properties}
 * that is no longer a valid properties file (#112) and an entry copied under another reference
 * (#113).
 */
class CorruptCredentialFilePropertiesTest {

    /** Fixed so CI is reproducible; jqwik prints the seed and the shrunk sample on failure. */
    private static final String SEED = "98065";
    private static final Map<String, String> SECRETS = new LinkedHashMap<>();

    static {
        SECRETS.put("ref-a", "secret-value-a");
        SECRETS.put("ref-b", "");
        SECRETS.put("payer/ref c", "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n");
    }

    private static Path root;
    private static byte[] pristineKey;
    private static byte[] pristineSecrets;
    private static Path store;

    /** One byte-level edit; positions are fractions of the file length so they shrink with the file. */
    record Edit(Kind kind, double at, byte[] bytes) {
        enum Kind { SET, INSERT, DELETE, TRUNCATE }

        byte[] apply(byte[] input) {
            int pos = (int) (at * input.length);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            switch (kind) {
                case SET -> {
                    out.write(input, 0, pos);
                    out.write(bytes, 0, Math.min(bytes.length, input.length - pos));
                    int end = Math.min(input.length, pos + bytes.length);
                    out.write(input, end, input.length - end);
                }
                case INSERT -> {
                    out.write(input, 0, pos);
                    out.write(bytes, 0, bytes.length);
                    out.write(input, pos, input.length - pos);
                }
                case DELETE -> {
                    int end = Math.min(input.length, pos + Math.max(1, bytes.length));
                    out.write(input, 0, pos);
                    out.write(input, end, input.length - end);
                }
                case TRUNCATE -> out.write(input, 0, pos);
            }
            return out.toByteArray();
        }

        @Override
        public String toString() {
            return kind + "@" + at + (kind == Kind.SET || kind == Kind.INSERT
                    ? "[" + new String(bytes, StandardCharsets.ISO_8859_1) + "]" : "");
        }
    }

    @BeforeContainer
    static void writePristineStore() throws IOException {
        root = Files.createTempDirectory("corrupt-credential-properties");
        Path pristine = root.resolve("pristine");
        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(pristine);
        SECRETS.forEach(provider::put);
        pristineKey = Files.readAllBytes(pristine.resolve("key.bin"));
        pristineSecrets = Files.readAllBytes(pristine.resolve("secrets.properties"));
        store = root.resolve("store");
    }

    @AfterContainer
    static void deleteStores() throws IOException {
        try (Stream<Path> paths = Files.walk(root)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    @BeforeTry
    void clearStore() throws IOException {
        if (Files.exists(store)) {
            try (Stream<Path> paths = Files.walk(store)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
        Files.createDirectories(store);
    }

    @Property(seed = SEED)
    void corruptKeyFileIsADocumentedError(@ForAll("edits") List<Edit> edits) throws IOException {
        checkStore(apply(pristineKey, edits), pristineSecrets);
    }

    @Property(seed = SEED)
    void corruptSecretsFileIsADocumentedError(@ForAll("edits") List<Edit> edits) throws IOException {
        checkStore(pristineKey, apply(pristineSecrets, edits));
    }

    @Property(seed = SEED)
    void corruptEntryValueIsADocumentedError(@ForAll("entryValues") Map<String, String> values) throws IOException {
        Properties properties = new Properties();
        properties.load(new ByteArrayInputStream(pristineSecrets));
        values.forEach(properties::setProperty);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        properties.store(out, null);
        checkStore(pristineKey, out.toByteArray());
    }

    /**
     * Each stored reference resolves to its own secret, to nothing, or to a documented error; a
     * later put never replaces the key file, and when it succeeds its secret reads back.
     */
    private static void checkStore(byte[] key, byte[] secrets) throws IOException {
        Files.write(store.resolve("key.bin"), key);
        Files.write(store.resolve("secrets.properties"), secrets);
        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(store);

        for (Map.Entry<String, String> secret : SECRETS.entrySet()) {
            documented(() -> provider.resolve(secret.getKey()))
                    .flatMap(resolved -> resolved)
                    .ifPresent(value -> assertEquals(secret.getValue(), value, "wrong secret for " + secret.getKey()));
        }
        boolean stored = documented(() -> {
            provider.put("new-ref", "new-secret");
            return true;
        }).isPresent();

        assertArrayEquals(key, Files.readAllBytes(store.resolve("key.bin")), "key.bin was replaced");
        if (stored) {
            assertEquals(Optional.of("new-secret"), new EncryptedLocalCredentialProvider(store).resolve("new-ref"));
        }
    }

    private interface Call<T> {
        T run();
    }

    /** Runs {@code call}; a documented failure is empty, anything else escapes and fails the property. */
    private static <T> Optional<T> documented(Call<T> call) {
        try {
            return Optional.of(call.run());
        } catch (IllegalStateException | UncheckedIOException e) {
            assertNotNull(e.getMessage());
            for (Throwable t = e; t != null; t = t.getCause()) {
                String message = String.valueOf(t.getMessage());
                SECRETS.values().stream().filter(s -> s.length() > 4)
                        .forEach(s -> assertFalse(message.contains(s), "message leaks a secret: " + message));
            }
            return Optional.empty();
        }
    }

    private static byte[] apply(byte[] input, List<Edit> edits) {
        byte[] out = input;
        for (Edit edit : edits) {
            out = edit.apply(out);
        }
        return out;
    }

    @Provide
    Arbitrary<List<Edit>> edits() {
        Arbitrary<byte[]> payload = Arbitraries.oneOf(
                Arbitraries.bytes().array(byte[].class).ofMinSize(1).ofMaxSize(4),
                // Bytes that mean something to Properties.load, base64 or the AES-GCM layout.
                Arbitraries.of("\\", "\\u", "\\u00", "=", ":", "#", "!", " ", "\n", "\r", "\t", "A", "/", "+", "==",
                                "\u0000", "ÿ")
                        .map(s -> s.getBytes(StandardCharsets.ISO_8859_1)));
        Arbitrary<Edit> edit = Combinators.combine(Arbitraries.of(Edit.Kind.class),
                Arbitraries.doubles().between(0, 1).ofScale(4), payload).as(Edit::new);
        return edit.list().ofMinSize(1).ofMaxSize(4);
    }

    /**
     * Replacement ciphertext for some stored entries: re-encoded byte edits with or without the
     * {@code v2:} prefix, another reference's entry verbatim, or any text.
     */
    @Provide
    Arbitrary<Map<String, String>> entryValues() throws IOException {
        Properties properties = new Properties();
        properties.load(new ByteArrayInputStream(pristineSecrets));
        List<String> refs = new ArrayList<>(SECRETS.keySet());
        Arbitrary<String> ref = Arbitraries.of(refs);
        Arbitrary<String> value = Combinators.combine(ref, edits(), Arbitraries.of(true, false), Arbitraries.of("v2:", ""))
                .as((r, edits, base64, prefix) -> {
                    byte[] decoded = Base64.getDecoder().decode(properties.getProperty(r).substring("v2:".length()));
                    byte[] edited = apply(decoded, edits);
                    return prefix + (base64 ? Base64.getEncoder().encodeToString(edited)
                            : HexFormat.of().formatHex(edited));
                });
        Arbitrary<String> copied = ref.map(properties::getProperty);
        Arbitrary<String> text = Arbitraries.strings().ofMaxLength(40);
        return Arbitraries.maps(ref, Arbitraries.frequencyOf(Tuple.of(4, value), Tuple.of(2, copied), Tuple.of(1, text)))
                .ofMinSize(1).ofMaxSize(refs.size());
    }
}
