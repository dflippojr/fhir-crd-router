package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** #99: the connection file is never readable by others, not even between creating a file and finishing it. */
@EnabledOnOs({OS.LINUX, OS.MAC})
class PermissionWindowTest {

    /**
     * A child JVM runs with umask 000, so a file created with default permissions and chmod'd later
     * would be world-readable until the chmod. Each temporary file is checked the moment the create
     * call returns, before the store can chmod it: the create call must have been given owner-only
     * permissions and the new file must already have them. When its content is serialized, every
     * temporary file in the directory must be one of those, so a file created some other way fails.
     */
    @Test
    void aNewConnectionFileIsOwnerOnlyFromCreationUnderAPermissiveUmask(@TempDir Path dir) throws Exception {
        Process child = new ProcessBuilder("/bin/sh", "-c", "umask 000 && exec \"$@\"", "sh",
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Xmx64m", "-XX:+UseSerialGC", "-XX:TieredStopAtLevel=1",
                "-cp", System.getProperty("java.class.path"), UmaskProcess.class.getName(), dir.toString())
                .redirectErrorStream(true)
                .start();
        String output = new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, child.waitFor(), "child failed:\n" + output);
        List<String> report = output.lines().toList();

        assertTrue(report.contains("control rw-rw-rw-"),
                "umask 000 was not in effect in the child, so the check proves nothing: " + report);
        assertEquals(List.of("create attrs rw------- file rw-------", "create attrs rw------- file rw-------"),
                report.stream().filter(line -> line.startsWith("create ")).toList());
        assertEquals(List.of("tmp rw------- created owner-only", "tmp rw------- created owner-only"),
                report.stream().filter(line -> line.startsWith("tmp ")).toList());
        assertTrue(report.contains("file rw-------"), report.toString());
        assertEquals("rw-------",
                PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve("connections.yaml"))));
    }

    /**
     * Child process: saves twice (creating the file, then replacing it). It reports the permissions
     * asked for and found when each temporary file is created, the temporary files present when the
     * records are serialized, then the connection file and a control file created with default
     * permissions.
     */
    public static final class UmaskProcess {
        public static void main(String[] args) throws IOException {
            Path dir = Path.of(args[0]);
            Set<Path> created = new HashSet<>();
            FileBasedConnectionStore.TempFileCreator checking = (parent, prefix, suffix, attrs) -> {
                Path tmp = Files.createTempFile(parent, prefix, suffix, attrs);
                System.out.println("create attrs " + requested(attrs) + " file " + permissions(tmp));
                created.add(tmp);
                return tmp;
            };
            ObjectMapper reporting = new ObjectMapper(new YAMLFactory()) {
                @Override
                public void writeValue(OutputStream out, Object value) throws IOException {
                    reportTemporaries(dir, created);
                    super.writeValue(out, value);
                }
            }.registerModule(new JavaTimeModule()).disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
            var store = new FileBasedConnectionStore(dir.resolve("connections.yaml"), reporting,
                    (tmp, target) -> Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE), checking);
            for (String payerId : List.of("PAYER-A", "PAYER-B")) {
                store.save(ConnectionRecord.builder().payerId(payerId).environment(Environment.SANDBOX)
                        .baseUrl("https://payer.example.test/cds").authType(AuthType.NONE).build());
            }
            System.out.println("file " + permissions(dir.resolve("connections.yaml")));
            System.out.println("control " + permissions(Files.createFile(dir.resolve("control"))));
        }

        private static void reportTemporaries(Path dir, Set<Path> created) {
            try (Stream<Path> files = Files.list(dir)) {
                for (Path tmp : files.filter(f -> f.getFileName().toString().endsWith(".tmp")).toList()) {
                    System.out.println("tmp " + permissions(tmp)
                            + (created.contains(tmp) ? " created owner-only" : " created some other way"));
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
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

        private static String permissions(Path file) throws IOException {
            return PosixFilePermissions.toString(Files.getPosixFilePermissions(file));
        }
    }
}
