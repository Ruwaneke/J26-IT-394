package com.sentinel.feedback.policy;

import com.sentinel.feedback.model.Severity;

import java.util.List;

/** Policy v1.0.0 as in policy.yaml, for unit tests that run without Spring. */
public final class TestPolicies {

    private TestPolicies() {
    }

    public static PolicyProperties defaults() {
        return new PolicyProperties(
                "1.0.0",
                new PolicyProperties.Weights(35, 20, 20, 15, 10),
                3,
                new PolicyProperties.Recency(7, 14),
                new PolicyProperties.Levels(30, 55, 80),
                new PolicyProperties.Mastery(0.5, 0.25, 0.15, 0.30, 0.20, 30, 0.75),
                List.of(
                        new PolicyProperties.LevelOverride("CWE-798", null, 3, "secret floor"),
                        new PolicyProperties.LevelOverride(null, Severity.CRITICAL, 2,
                                "critical floor")));
    }
}
