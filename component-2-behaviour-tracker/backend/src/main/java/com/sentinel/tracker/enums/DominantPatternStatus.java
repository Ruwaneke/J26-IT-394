package com.sentinel.tracker.enums;

/**
 * Whether one complete response sequence is clearly the developer's most frequent one.
 * INSUFFICIENT_DATA covers too few sequences, too little support, and ties.
 */
public enum DominantPatternStatus {
    FOUND,
    INSUFFICIENT_DATA
}
