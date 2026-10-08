package io.github.dflippojr.fhircrdrouter.core.audit;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Read-only owner API. Scans the whole file for integrity, retaining only bounded matches. */
public final class AuditReader {
    private final Path path;
    public AuditReader(Path path) { this.path = Objects.requireNonNull(path, "path"); }

    public record Result(List<AuditEvent> events, boolean incompleteFinalLine, boolean limitReached) {
        public Result { events = List.copyOf(events); }
    }

    public Result query(AuditQuery query) {
        Objects.requireNonNull(query, "query");
        if (!Files.exists(path)) return new Result(List.of(), false, false);
        try (var input = Files.newInputStream(path)) {
            return scan(input, query);
        } catch (IOException e) {
            throw new AuditReadException(1);
        }
    }

    static Result scan(InputStream source, AuditQuery query) {
        List<AuditEvent> events = new ArrayList<>();
        long lineNumber = 1;
        boolean limitReached = false;
        try (var input = new BufferedInputStream(source);
             var line = new ByteArrayOutputStream()) {
            int value;
            while ((value = input.read()) != -1) {
                if (value != '\n') {
                    if (line.size() >= 65_536) throw new AuditReadException(lineNumber);
                    line.write(value);
                    continue;
                }
                AuditEvent event = AuditJson.decode(line.toByteArray());
                if (query.matches(event)) {
                    if (events.size() < query.limit()) events.add(event);
                    else limitReached = true;
                }
                line.reset();
                lineNumber++;
            }
            return new Result(events, line.size() != 0, limitReached);
        } catch (IOException | IllegalArgumentException e) {
            throw new AuditReadException(lineNumber);
        }
    }

    /** Caller owns and secures destination; it is not a writable handle to the source trail. */
    public Result exportJsonl(AuditQuery query, OutputStream destination) throws IOException {
        Objects.requireNonNull(destination, "destination");
        Result result = query(query);
        for (AuditEvent event : result.events()) {
            destination.write(AuditJson.encode(event));
            destination.write('\n');
        }
        destination.flush();
        return result;
    }
}
