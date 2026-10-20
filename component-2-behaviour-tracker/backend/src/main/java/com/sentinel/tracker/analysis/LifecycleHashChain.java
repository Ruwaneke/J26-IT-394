package com.sentinel.tracker.analysis;

import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Hash chain over the lifecycle history of one security event (tamper evidence).
 *
 * <p>Each entry stores {@code prevHash}, the {@code entryHash} of the entry before it (or
 * {@link #GENESIS_HASH} for the first chained entry), and its own
 * {@code entryHash = SHA-256(prevHash|securityEventId|previousStatus|newStatus|changedAt|changedBy)},
 * hex-encoded, with {@code null} written as an empty string. Entries are chained in id order,
 * which is insertion order. Editing, deleting or reordering an entry breaks the chain from that
 * point on.
 *
 * <p>Tamper-evident, not tamper-proof: someone with write access to the database who knows
 * this algorithm can rebuild the chain, and deleting the newest entries leaves no trace.
 */
public final class LifecycleHashChain {

    /** {@code prevHash} of the first chained entry of each event. */
    public static final String GENESIS_HASH = "0".repeat(64);

    private static final char SEPARATOR = '|';
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSS");

    private LifecycleHashChain() {
    }

    /**
     * Truncates a timestamp to microseconds, the precision PostgreSQL stores. A history row's
     * {@code changedAt} must be truncated before it is saved, or the value read back (which
     * PostgreSQL rounds) no longer matches the hash.
     */
    public static LocalDateTime normalise(LocalDateTime timestamp) {
        return timestamp == null ? null : timestamp.truncatedTo(ChronoUnit.MICROS);
    }

    /**
     * The {@code prevHash} for a new entry, given the event's latest existing entry. Without a
     * chained predecessor (no entry yet, or only entries written before the chain existed) the
     * chain starts at {@link #GENESIS_HASH}.
     */
    public static String nextPrevHash(Optional<VulnerabilityLifecycleHistory> latest) {
        return latest.map(VulnerabilityLifecycleHistory::getEntryHash).orElse(GENESIS_HASH);
    }

    /**
     * Normalises {@code changedAt} and sets {@code prevHash} and {@code entryHash} on a new
     * entry. Call it just before saving; the security event must already have an id.
     */
    public static void seal(VulnerabilityLifecycleHistory entry, String prevHash) {
        entry.setChangedAt(normalise(entry.getChangedAt()));
        entry.setPrevHash(prevHash);
        entry.setEntryHash(computeEntryHash(prevHash, entry));
    }

    /**
     * Computes the hash of an entry's stored fields, chained to {@code prevHash}.
     */
    public static String computeEntryHash(String prevHash, VulnerabilityLifecycleHistory entry) {
        StringBuilder input = new StringBuilder(256)
                .append(nullToEmpty(prevHash)).append(SEPARATOR)
                .append(entry.getSecurityEvent() != null ? nullToEmpty(entry.getSecurityEvent().getId()) : "")
                .append(SEPARATOR)
                .append(nullToEmpty(entry.getPreviousStatus())).append(SEPARATOR)
                .append(nullToEmpty(entry.getNewStatus())).append(SEPARATOR)
                .append(entry.getChangedAt() != null ? TIMESTAMP_FORMAT.format(normalise(entry.getChangedAt())) : "")
                .append(SEPARATOR)
                .append(nullToEmpty(entry.getChangedBy()));
        return sha256Hex(input.toString());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String nullToEmpty(Object value) {
        return value == null ? "" : value.toString();
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            // Every Java platform is required to support SHA-256
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
