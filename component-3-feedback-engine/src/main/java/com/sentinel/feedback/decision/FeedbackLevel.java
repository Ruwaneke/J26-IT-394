package com.sentinel.feedback.decision;

import java.util.Arrays;

public enum FeedbackLevel {
    L1(1, "Nudge"),
    L2(2, "Guide"),
    L3(3, "Coach"),
    L4(4, "Intervene");

    private final int number;
    private final String displayName;

    FeedbackLevel(int number, String displayName) {
        this.number = number;
        this.displayName = displayName;
    }

    public int number() {
        return number;
    }

    public String displayName() {
        return displayName;
    }

    public static FeedbackLevel of(int number) {
        return Arrays.stream(values())
                .filter(level -> level.number == number)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No feedback level " + number));
    }
}
