package io.github.dflippojr.fhircrdrouter.credential.local;

import io.github.dflippojr.fhircrdrouter.core.internal.AtomicFiles;

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
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
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
     * would be world-readable until the chmod. Each temporary file is checked the moment the create
     * call returns, before the store can chmod it: the create call must have been given owner-only
     * permissions and the new file must already have them. At its first write, every temporary file
     * in the directory must be one of those, so a file created some other way fails.
     */
    @Test
    void bothFilesAreOwnerOnlyFromCreationUnderAPermissiveUmask(@TempDir Path dir) throws Exception {
        List<String> report = runUnderUmask000(UmaskProcess.class, dir.toString());

        assertTrue(report.contains("control rw-rw-rw-"),
                "umask 000 was not in effect in the child, so the check proves nothing: " + report);
        List<String> temporaries = report.stream().filter(line -> line.startsWith("tmp ")).toList();
        assertEquals(List.of("create key.bin attrs rw------- file rw-------",
                "create secrets.properties attrs rw------- file rw-------",
                "create secrets.properties attrs rw------- file rw-------"),
                report.stream().filter(line -> line.startsWith("create ")).toList());
        assertEquals(List.of("tmp key.bin rw------- created owner-only",
                "tmp secrets.properties rw------- created owner-only",
                "tmp secrets.properties rw------- created owner-only"), temporaries);
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
     * Child process: reports the permissions asked for and found when each temporary file is
     * created, every temporary file at its first write, then the files the store kept and a control
     * file created with default permissions.
     */
    public static final class UmaskProcess {
        public static void main(String[] args) throws IOException {
            Path dir = Path.of(args[0]);
            Set<Path> created = new HashSet<>();
            AtomicFiles.TempFileCreator checking = (parent, prefix, suffix, attrs) -> {
                Path tmp = Files.createTempFile(parent, prefix, suffix, attrs);
                System.out.println("create " + target(tmp) + " attrs " + requested(attrs) + " file " + permissions(tmp));
                created.add(tmp);
                return tmp;
            };
            var provider = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO, System::nanoTime,
                    out -> new FilterOutputStream(out) {
                        private boolean checked;

                        @Override
                        public void write(byte[] b, int off, int len) throws IOException {
                            if (!checked) {
                                checked = true;
                                reportTemporaries(dir, created);
                            }
                            out.write(b, off, len);
                        }
                    }, checking);
            provider.put("a", SECRET);
            provider.put("b", SECRET);
            for (String name : List.of("key.bin", "secrets.properties", "secrets.lock")) {
                System.out.println("file " + name + " " + permissions(dir.resolve(name)));
            }
            Path control = Files.createFile(dir.resolve("control"));
            System.out.println("control " + permissions(control));
        }

        private static void reportTemporaries(Path dir, Set<Path> created) {
            try (Stream<Path> files = Files.list(dir)) {
                for (Path tmp : files.filter(f -> f.getFileName().toString().endsWith(".tmp")).toList()) {
                    System.out.println("tmp " + target(tmp) + " " + permissions(tmp)
                            + (created.contains(tmp) ? " created owner-only" : " created some other way"));
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        /** The file a {@code <target>.*.tmp} file is for. */
        private static String target(Path tmp) {
            String name = tmp.getFileName().toString();
            return name.substring(0, name.indexOf(".", name.indexOf('.') + 1));
        }

        /** The POSIX permissions the create call was given, or "none". */
        @SuppressWarnings("unchecked")
        private static String requested(FileAttribute<?>... attrs) {
            for (FileAttribute<?> attr : attrs) {
                if (attr.name().equals("posix:permissions")) {
                    return PosixFilePermissions.toString((Set<PosixFilePermission>) attr.value());
                }
            }
            return "none";
        }
    }
}
