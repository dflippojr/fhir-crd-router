package io.github.dflippojr.fhircrdrouter.core.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

final class AuditJson {
    private static final ObjectMapper MAPPER = new ObjectMapper().registerModule(new JavaTimeModule())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private AuditJson() { }
    record Line(AuditEvent event, String sha256) { }

    static byte[] encode(AuditEvent event) throws IOException {
        return MAPPER.writeValueAsBytes(new Line(event, checksum(event)));
    }

    static AuditEvent decode(byte[] bytes) throws IOException {
        Line line = MAPPER.readValue(bytes, Line.class);
        if (line == null || line.event() == null || !checksum(line.event()).equals(line.sha256())) {
            throw new IOException("Invalid audit checksum");
        }
        return line.event();
    }

    private static String checksum(AuditEvent event) throws IOException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(MAPPER.writeValueAsBytes(event)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK requires SHA-256", e);
        }
    }
}
