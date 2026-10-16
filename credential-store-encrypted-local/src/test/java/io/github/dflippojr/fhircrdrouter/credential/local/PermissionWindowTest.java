package io.github.dflippojr.fhircrdrouter.credential.local;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * #99, #73 lead 3: {@code key.bin} and {@code secrets.properties} are never readable by others, not
 * even between creating a file and finishing it, and a {@code key.bin} that others can read is
 * restricted when it is loaded.
 */
@EnabledOnOs({OS.LINUX, OS.MAC})
class PermissionWindowTest {

    private static final String SECRET = "synthetic-permission-window-secret";

    /**
     * A child JVM runs with umask 000, so a file created with default permissions and chmod'd later
     * would be world-readable until the chmod. Each temporary file is checked at its first write,
     * before any content reaches it.
     */
    @Test
    void bothFilesAreOwnerOnlyFromCreationUnderAPermissiveUmask(@TempDir Path dir) throws Exception {
        List<String> report = runUnderUmask000(UmaskProcess.class, dir.toString());

        assertTrue(report.contains("control rw-rw-rw-"),
                "umask 000 was not in effect in the child, so the check proves nothing: " + report);
        List<String> temporaries = report.stream().filter(line -> line.startsWith("tmp ")).toList();
        assertEquals(List.of("tmp key.bin rw-------", "tmp secrets.properties rw-------",
                "tmp secrets.properties rw-------"), temporaries);
        for (String name : List.of("key.bin", "secrets.properties", "secrets.lock")) {
            assertTrue(report.contains("file " + name + " rw-------"), name + ": " + report);
            assertEquals("rw-------", permissions(dir.resolve(name)), name);
        }
    }

    @Test
    void resolveRestrictsAKeyThatOthersCanRead(@TempDir Path dir) throws Exception {
        new EncryptedLocalCredentialProvider(dir).put("ref", SECRET);
        Path keyFile = dir.resolve("key.bin");
        byte[] key = Files.readAllBytes(keyFile);
        Files.setPosixFilePermissions(keyFile, PosixFilePermissions.fromString("rw-r--r--"));

        assertEquals(Optional.of(SECRET), new EncryptedLocalCredentialProvider(dir).resolve("ref"));
        assertEquals("rw-------", permissions(keyFile));
        assertArrayEquals(key, Files.readAllBytes(keyFile), "restricting must not touch the key");
    }

    @Test
    void putRestrictsAKeyOnlyItsGroupCanReadAndKeepsTheOwnerBits(@TempDir Path dir) throws Exception {
        new EncryptedLocalCredentialProvider(dir).put("ref", SECRET);
        Path keyFile = dir.resolve("key.bin");
        Files.setPosixFilePermissions(keyFile, PosixFilePermissions.fromString("r--rw----"));

        var provider = new EncryptedLocalCredentialProvider(dir);
        provider.put("other", SECRET);
        assertEquals("r--------", permissions(keyFile), "only group and other bits are taken off");
        assertEquals(Optional.of(SECRET), provider.resolve("ref"));
    }

    @Test
    void anOwnerOnlyKeyIsLeftAsItIs(@TempDir Path dir) throws Exception {
        new EncryptedLocalCredentialProvider(dir).put("ref", SECRET);
        Path keyFile = dir.resolve("key.bin");
        Files.setPosixFilePermissions(keyFile, PosixFilePermissions.fromString("r--------"));

        assertEquals(Optional.of(SECRET), new EncryptedLocalCredentialProvider(dir).resolve("ref"));
        assertEquals("r--------", permissions(keyFile));
    }

    /**
     * {@code key.bin} is a link to a file another user owns and others can read, so its permissions
     * cannot be changed: loading fails instead of using a key that others can read.
     */
    @Test
    void aKeyOthersCanReadThatCannotBeRestrictedFailsLoudly(@TempDir Path dir) throws Exception {
        Path foreign = Path.of("/etc/passwd");
        assumeTrue(Files.isReadable(foreign) && permissions(foreign).endsWith("r--"),
                "needs a world-readable file owned by another user");
        assumeFalse(Files.getOwner(foreign).getName().equals(System.getProperty("user.name")),
                "the test user owns " + foreign + ", so its permissions could be changed");
        new EncryptedLocalCredentialProvider(dir).put("ref", SECRET);
        Path keyFile = dir.resolve("key.bin");
        Files.delete(keyFile);
        Files.createSymbolicLink(keyFile, foreign);
        String before = permissions(foreign);

        var provider = new EncryptedLocalCredentialProvider(dir);
        IllegalStateException failure = assertThrows(IllegalStateException.class, () -> provider.resolve("ref"));
        assertTrue(failure.getMessage().contains("could not be restricted to its owner"), failure.getMessage());
        assertTrue(failure.getMessage().contains(before), failure.getMessage());
        assertFalse(failure.getMessage().contains(SECRET), failure.getMessage());
        assertEquals(before, permissions(foreign));
        assertThrows(IllegalStateException.class, () -> provider.put("other", SECRET),
                "put must refuse the key as well");
    }

    private static String permissions(Path file) throws IOException {
        return PosixFilePermissions.toString(Files.getPosixFilePermissions(file));
    }

    /** Runs {@code main} in a child JVM whose umask is 000 and returns its standard output lines. */
    static List<String> runUnderUmask000(Class<?> main, String... args) throws Exception {
        List<String> command = new ArrayList<>(List.of("/bin/sh", "-c", "umask 000 && exec \"$@\"", "sh",
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Xmx64m", "-XX:+UseSerialGC", "-XX:TieredStopAtLevel=1",
                "-cp", System.getProperty("java.class.path"), main.getName()));
        command.addAll(List.of(args));
        Process child = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, child.waitFor(), "child failed:\n" + output);
        return output.lines().toList();
    }

    /**
     * Child process: reports the permissions of every temporary file at its first write, then of
     * the files the store kept, and of a control file created with default permissions.
     */
    public static final class UmaskProcess {
        public static void main(String[] args) throws IOException {
            Path dir = Path.of(args[0]);
            var provider = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO, System::nanoTime,
                    out -> new FilterOutputStream(out) {
                        private boolean checked;

                        @Override
                        public void write(byte[] b, int off, int len) throws IOException {
                            if (!checked) {
                                checked = true;
                                reportTemporaries(dir);
                            }
                            out.write(b, off, len);
                        }
                    });
            provider.put("a", SECRET);
            provider.put("b", SECRET);
            for (String name : List.of("key.bin", "secrets.properties", "secrets.lock")) {
                System.out.println("file " + name + " " + permissions(dir.resolve(name)));
            }
            Path control = Files.createFile(dir.resolve("control"));
            System.out.println("control " + permissions(control));
        }

        private static void reportTemporaries(Path dir) {
            try (Stream<Path> files = Files.list(dir)) {
                for (Path tmp : files.filter(f -> f.getFileName().toString().endsWith(".tmp")).toList()) {
                    String name = tmp.getFileName().toString();
                    System.out.println("tmp " + name.substring(0, name.indexOf(".", name.indexOf('.') + 1))
                            + " " + permissions(tmp));
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }
}
