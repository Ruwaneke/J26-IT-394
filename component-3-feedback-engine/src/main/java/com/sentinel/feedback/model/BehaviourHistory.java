package com.sentinel.feedback.model;

import jakarta.validation.constraints.NotBlank;

import java.util.Map;

public record BehaviourHistory(
        @NotBlank String developerId,
        int previousFindings,
        int previousFixes,
        int previousIgnores,
        Map<VulnerabilityType, Integer> findingsByType
) {
    public BehaviourHistory {
        findingsByType = findingsByType == null ? Map.of() : Map.copyOf(findingsByType);
    }

    public int previousFindingsFor(VulnerabilityType vulnerabilityType) {
        return findingsByType.getOrDefault(vulnerabilityType, 0);
    }
}
