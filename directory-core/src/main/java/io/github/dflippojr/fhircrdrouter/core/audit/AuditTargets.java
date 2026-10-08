package io.github.dflippojr.fhircrdrouter.core.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.regex.Pattern;

/** Turns caller-chosen references into audit-safe opaque target IDs. */
public final class AuditTargets {
    private static final Pattern SAFE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}");

    private AuditTargets() { }

    /** A reference that already is a safe label is kept; anything else becomes a digest label. */
    public static String opaque(String reference) {
        if (reference != null && SAFE.matcher(reference).matches()) return reference;
        return "ref-" + digest(reference == null ? "" : reference, 16);
    }

    /** Leading hex characters of SHA-256; used for references and store identities, never secrets. */
    public static String digest(String value, int hexChars) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, hexChars);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
