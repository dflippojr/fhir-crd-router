package io.github.dflippojr.fhircrdrouter.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * #99: a writer killed with SIGKILL at a random point never costs an acknowledged record and never
 * leaves a connection file that fails to load.
 *
 * <p>Four lanes run at once, each with its own directory and at most one child JVM at a time (the
 * store is single-process). A child loops {@code save}, {@code delete} and the first {@code save}
 * to a new file, logging each operation to a side log before it starts and again once it returns.
 * The lane kills it after a random delay with {@link Process#destroyForcibly()} and checks the files
 * with fresh instances, then starts the next child on the same directory. On POSIX the child runs
 * with umask 000, so a file that is not owner-only from creation shows up in the permissions check.
 *
 * <p>The seed is printed; {@code -Dcrash.seed=<seed>} repeats the same operations and kill delays
 * (where a kill lands still depends on timing).
 */
class CrashDurabilityIT {

    private static final int LANES = 4;
    private static final int ITERATIONS_PER_LANE = 25;
    private static final int MAX_KILL_DELAY_MS = 250;
    private static final boolean POSIX = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void aKilledWriterNeverLosesAnAcknowledgedRecord(@TempDir Path root) throws Exception {
        long seed = Long.getLong("crash.seed", System.nanoTime());
        System.out.println("CrashDurabilityIT (connection store): seed " + seed + ", " + LANES + " lanes x "
                + ITERATIONS_PER_LANE + " kills; rerun with -Dcrash.seed=" + seed);
        long started = System.nanoTime();
        Random seeds = new Random(seed);
        ExecutorService pool = Executors.newFixedThreadPool(LANES);
        List<LaneResult> results = new ArrayList<>();
        try {
            List<Future<LaneResult>> lanes = new ArrayList<>();
            for (int lane = 0; lane < LANES; lane++) {
                Lane task = new Lane(lane, root.resolve("lane-" + lane), seeds.nextLong());
                lanes.add(pool.submit(task::run));
            }
            for (Future<LaneResult> lane : lanes) {
                results.add(lane.get());
            }
        } finally {
            pool.shutdownNow();
        }

        int kills = results.stream().mapToInt(LaneResult::kills).sum();
        int acknowledged = results.stream().mapToInt(LaneResult::acknowledged).sum();
        int inFlight = results.stream().mapToInt(LaneResult::killedMidOperation).sum();
        int filesCreated = results.stream().mapToInt(LaneResult::filesCreated).sum();
        int temporaryFiles = results.stream().mapToInt(LaneResult::temporaryFilesLeft).sum();
        System.out.printf("CrashDurabilityIT (connection store): seed %d, %d kills (%d mid-operation), "
                        + "%d acknowledged operations, %d first saves to a new file, %d temporary files left, %d ms%n",
                seed, kills, inFlight, acknowledged, filesCreated, temporaryFiles,
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
        results.forEach(r -> System.out.println("  " + r));
        assertEquals(LANES * ITERATIONS_PER_LANE, kills);
        assertTrue(acknowledged > kills, "the children barely ran; the kills tested little");
    }

    record LaneResult(int lane, long seed, int kills, int acknowledged, int killedMidOperation, int filesCreated,
                      int temporaryFilesLeft, List<Long> iterationSeeds) {
        @Override
        public String toString() {
            return "lane " + lane + " seed " + seed + ": " + kills + " kills, " + acknowledged + " acknowledged, "
                    + killedMidOperation + " mid-operation, " + filesCreated + " new files, "
                    + temporaryFilesLeft + " temporary files left; iteration seeds " + iterationSeeds;
        }
    }

    /** One directory, killed and checked {@link #ITERATIONS_PER_LANE} times. */
    private static final class Lane {
        private final int lane;
        private final Path dir;
        private final long seed;
        private final Path log;
        private int leftovers;

        Lane(int lane, Path dir, long seed) {
            this.lane = lane;
            this.dir = dir;
            this.seed = seed;
            this.log = dir.resolve("operations.log");
        }

        LaneResult run() throws Exception {
            Files.createDirectories(dir);
            Random random = new Random(seed);
            List<Long> iterationSeeds = new ArrayList<>();
            int midOperation = 0;
            for (int iteration = 0; iteration < ITERATIONS_PER_LANE; iteration++) {
                long iterationSeed = random.nextLong();
                iterationSeeds.add(iterationSeed);
                Process child = start(iteration, iterationSeed);
                try {
                    awaitReady(child);
                    Thread.sleep(new Random(iterationSeed).nextInt(MAX_KILL_DELAY_MS));
                } finally {
                    child.destroyForcibly();
                    child.waitFor();
                }
                String where = "lane " + lane + " iteration " + iteration + " seed " + iterationSeed;
                Operations operations = Operations.read(log);
                check(operations, iteration, where);
                if (operations.lastIsInFlight()) {
                    midOperation++;
                }
            }
            Operations operations = Operations.read(log);
            return new LaneResult(lane, seed, ITERATIONS_PER_LANE, operations.acknowledged.size(), midOperation,
                    operations.acknowledgedOf("create").size(), leftovers, iterationSeeds);
        }

        private Process start(int iteration, long iterationSeed) throws IOException {
            List<String> command = new ArrayList<>();
            if (POSIX) {
                command.addAll(List.of("/bin/sh", "-c", "umask 000 && exec \"$@\"", "sh"));
            }
            command.addAll(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                    "-Xmx48m", "-XX:+UseSerialGC", "-XX:TieredStopAtLevel=1",
                    "-cp", System.getProperty("java.class.path"), WriterProcess.class.getName(),
                    dir.toString(), log.toString(), String.valueOf(iteration), String.valueOf(iterationSeed)));
            return new ProcessBuilder(command).redirectErrorStream(true).start();
        }

        private static void awaitReady(Process child) throws IOException {
            BufferedReader out = new BufferedReader(new InputStreamReader(child.getInputStream(), StandardCharsets.UTF_8));
            String line;
            StringBuilder seen = new StringBuilder();
            while ((line = out.readLine()) != null) {
                if (line.equals(WriterProcess.READY)) {
                    return;
                }
                seen.append(line).append('\n');
            }
            throw new IllegalStateException("child exited before it was ready:\n" + seen);
        }

        private void check(Operations operations, int iteration, String where) throws IOException {
            var fresh = new FileBasedConnectionStore(dir.resolve("connections.yaml"));
            Map<String, ConnectionRecord> stored = fresh.findAll().stream()
                    .collect(Collectors.toMap(ConnectionRecord::payerId, r -> r));
            for (String payerId : operations.started("save")) {
                Optional<ConnectionRecord> found = Optional.ofNullable(stored.get(payerId));
                if (operations.isAcknowledged("delete", payerId)) {
                    assertEquals(Optional.empty(), found, where + ": acknowledged delete of " + payerId + " was lost");
                } else if (operations.isAcknowledged("save", payerId) && !operations.wasStarted("delete", payerId)) {
                    assertTrue(found.isPresent(), where + ": acknowledged save of " + payerId + " was lost");
                    assertEquals(record(payerId), found.get(), where + ": " + payerId);
                } else {
                    found.ifPresent(r -> assertEquals(record(payerId), r,
                            where + ": in-flight operation on " + payerId + " left a wrong record"));
                }
            }
            Set<String> unknown = new HashSet<>(stored.keySet());
            unknown.removeAll(operations.started("save"));
            assertEquals(Set.of(), unknown, where + ": the store holds records nobody saved");

            for (String name : operations.started("create")) {
                if (name.startsWith("P-i" + iteration + "-")) {
                    checkFirstSave(dir.resolve("first-use").resolve(name + ".yaml"), name,
                            operations.isAcknowledged("create", name), where);
                }
            }
            checkPermissions(where);
            // #120: nothing removes the temporary file of a write that a kill interrupted, so "no .tmp
            // files are left behind" does not hold yet. Until it does, a kill may leave at most one.
            leftovers = temporaryFiles().size();
            assertTrue(leftovers <= iteration + 1, where + ": more temporary files than kills: " + temporaryFiles());
        }

        private List<Path> temporaryFiles() throws IOException {
            try (Stream<Path> files = Files.walk(dir)) {
                return files.filter(f -> f.getFileName().toString().endsWith(".tmp")).map(dir::relativize).toList();
            }
        }

        /** A new file whose first save was acknowledged holds it; one whose first save was killed may or may not. */
        private static void checkFirstSave(Path file, String payerId, boolean acknowledged, String where) {
            List<ConnectionRecord> all = new FileBasedConnectionStore(file).findAll();
            if (acknowledged) {
                assertEquals(List.of(record(payerId)), all,
                        where + ": acknowledged first save to " + file.getFileName() + " was lost");
            } else {
                assertTrue(all.isEmpty() || all.equals(List.of(record(payerId))), where + ": " + file.getFileName());
            }
        }

        /** Every file in the lane is owner-only where POSIX applies, including temporary files a kill left. */
        private void checkPermissions(String where) throws IOException {
            if (!POSIX) {
                return;
            }
            try (Stream<Path> files = Files.walk(dir)) {
                for (Path file : files.filter(Files::isRegularFile).filter(f -> !f.equals(log)).toList()) {
                    assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)),
                            where + ": " + dir.relativize(file) + " is not owner-only");
                    String name = file.getFileName().toString();
                    assertTrue(name.endsWith(".yaml") || name.endsWith(".tmp"),
                            where + ": unexpected file " + dir.relativize(file));
                }
            }
        }
    }

    private static final Instant CREATED = Instant.parse("2026-01-01T00:00:00Z");

    /** The synthetic record the child saves under {@code payerId}. */
    static ConnectionRecord record(String payerId) {
        return ConnectionRecord.builder()
                .payerId(payerId)
                .displayName("Synthetic payer " + payerId)
                .environment(Environment.SANDBOX)
                .baseUrl("https://" + payerId.toLowerCase() + ".payer.example.test/cds")
                .authType(AuthType.NONE)
                .credentialRef("synthetic-ref-" + payerId)
                .createdAt(CREATED)
                .updatedAt(CREATED)
                .build();
    }

    /**
     * The side log: {@code begin <op> <name>} before an operation and {@code ack <op> <name>} once
     * it returned. The child that wrote a {@code begin} without an {@code ack} was killed during it.
     */
    private record Operations(Map<String, Set<String>> started, Map<String, Set<String>> acknowledgedByOp,
                              List<String> acknowledged, boolean lastIsInFlight) {

        static Operations read(Path log) throws IOException {
            Map<String, Set<String>> started = new HashMap<>();
            Map<String, Set<String>> acknowledgedByOp = new HashMap<>();
            List<String> acknowledged = new ArrayList<>();
            String last = "";
            if (Files.exists(log)) {
                String content = Files.readString(log, StandardCharsets.UTF_8);
                for (String line : content.substring(0, content.lastIndexOf('\n') + 1).split("\n")) {
                    String[] parts = line.split(" ");
                    if (parts.length != 3) {
                        continue;
                    }
                    Map<String, Set<String>> target = parts[0].equals("begin") ? started : acknowledgedByOp;
                    target.computeIfAbsent(parts[1], ignored -> new HashSet<>()).add(parts[2]);
                    if (parts[0].equals("ack")) {
                        acknowledged.add(line);
                    }
                    last = parts[0];
                }
            }
            return new Operations(started, acknowledgedByOp, acknowledged, last.equals("begin"));
        }

        Set<String> started(String op) {
            return started.getOrDefault(op, Set.of());
        }

        Set<String> acknowledgedOf(String op) {
            return acknowledgedByOp.getOrDefault(op, Set.of());
        }

        boolean wasStarted(String op, String name) {
            return started(op).contains(name);
        }

        boolean isAcknowledged(String op, String name) {
            return acknowledgedOf(op).contains(name);
        }
    }

    /**
     * Child process: loops writes on {@code <dir>/connections.yaml} and first saves to new files
     * under {@code <dir>/first-use} until it is killed, or until its parent goes away and its
     * standard input closes.
     */
    public static final class WriterProcess {
        static final String READY = "READY";

        public static void main(String[] args) throws IOException {
            Path dir = Path.of(args[0]);
            int iteration = Integer.parseInt(args[2]);
            Random random = new Random(Long.parseLong(args[3]));
            Thread watchdog = new Thread(() -> {
                try {
                    while (System.in.read() >= 0) {
                        // Wait for the parent to close the pipe.
                    }
                } catch (IOException ignored) {
                    // Treated as the parent going away.
                }
                Runtime.getRuntime().halt(2);
            });
            watchdog.setDaemon(true);
            watchdog.start();
            try (FileOutputStream log = new FileOutputStream(args[1], true)) {
                warmUp();
                var store = new FileBasedConnectionStore(dir.resolve("connections.yaml"));
                store.findAll();
                List<String> mine = new ArrayList<>();
                System.out.println(READY);
                System.out.flush();
                for (int n = 0; ; n++) {
                    String name = "P-i" + iteration + "-" + n;
                    int choice = random.nextInt(10);
                    if (choice < 6 || mine.isEmpty()) {
                        logLine(log, "begin save " + name);
                        store.save(record(name));
                        logLine(log, "ack save " + name);
                        mine.add(name);
                    } else if (choice < 9) {
                        String payerId = mine.remove(random.nextInt(mine.size()));
                        logLine(log, "begin delete " + payerId);
                        store.delete(payerId, Environment.SANDBOX);
                        logLine(log, "ack delete " + payerId);
                    } else {
                        logLine(log, "begin create " + name);
                        new FileBasedConnectionStore(dir.resolve("first-use").resolve(name + ".yaml")).save(record(name));
                        logLine(log, "ack create " + name);
                    }
                }
            }
        }

        /**
         * Saves and deletes a record in a scratch directory outside the lane, so class loading and
         * the first compilations happen before {@link #READY}. Otherwise a loaded machine spends the
         * whole kill window on the first save and the kills land before anything was acknowledged.
         */
        private static void warmUp() throws IOException {
            Path scratch = Files.createTempDirectory("crash-warm-up");
            try {
                var store = new FileBasedConnectionStore(scratch.resolve("connections.yaml"));
                store.save(record("P-warm-up"));
                store.delete("P-warm-up", Environment.SANDBOX);
            } finally {
                try (Stream<Path> files = Files.walk(scratch)) {
                    for (Path file : files.sorted(Comparator.reverseOrder()).toList()) {
                        Files.deleteIfExists(file);
                    }
                }
            }
        }

        /** One unbuffered write per line, so a kill can only cut the log between lines. */
        private static void logLine(FileOutputStream log, String line) {
            try {
                log.write((line + "\n").getBytes(StandardCharsets.UTF_8));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    }
}
