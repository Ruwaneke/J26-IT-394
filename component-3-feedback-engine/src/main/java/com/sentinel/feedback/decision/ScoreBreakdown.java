package com.sentinel.feedback.decision;

/** Points contributed by each factor of the priority score; they sum to the 0-100 total. */
public record ScoreBreakdown(
        double severity,
        double repeat,
        double ignore,
        double weakness,
        double recency
) {
    public double total() {
        return severity + repeat + ignore + weakness + recency;
    }

    public ScoreBreakdown rounded() {
        return new ScoreBreakdown(round2(severity), round2(repeat), round2(ignore),
                round2(weakness), round2(recency));
    }

    static double round2(double value) {
        return Math.round(value * 100.0) / 100.0;
    }
}
