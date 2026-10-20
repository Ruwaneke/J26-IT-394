package com.sentinel.tracker.enums;

/**
 * Result of verifying a security event's lifecycle hash chain.
 */
public enum HistoryIntegrityStatus {
    /** Every entry is chained and matches its hash. */
    VALID,
    /** The chain does not match: history was edited, deleted or reordered after it was written. */
    BROKEN,
    /**
     * Some or all entries were written before the hash chain existed and cannot be verified;
     * the chained entries after them are intact.
     */
    UNCHAINED
}
