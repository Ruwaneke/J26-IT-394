package com.sentinel.feedback.policy;

import com.sentinel.feedback.model.Severity;
import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * Decision policy loaded from {@code policy.yaml}. Rules decide the feedback level;
 * every number they use comes from here.
 */
@Validated
@ConfigurationProperties(prefix = "policy")
public record PolicyProperties(
        @NotBlank String version,
        @Valid @NotNull Weights weights,
        @Positive int pressureSaturation,
        boolean reopensCountAsRepeats,
        @Valid @NotNull Recency recency,
        @Valid @NotNull Levels levels,
        @Valid @NotNull Mastery mastery,
        @Valid List<LevelOverride> overrides,
        @Valid @NotNull Fatigue fatigue
) {
    public PolicyProperties {
        overrides = overrides == null ? List.of() : List.copyOf(overrides);
    }

    public record Weights(
            @Min(0) double severity,
            @Min(0) double repeat,
            @Min(0) double ignore,
            @Min(0) double weakness,
            @Min(0) double recency
    ) {
    }

    public record Recency(@Positive int fullDays, @Positive int halfDays) {
    }

    public record Levels(@Positive double l2, @Positive double l3, @Positive double l4) {
    }

    public record Mastery(
            @DecimalMin("0.0") @DecimalMax("1.0") double initial,
            @DecimalMin("0.0") @DecimalMax("1.0") double fixGain,
            @DecimalMin("0.0") @DecimalMax("1.0") double ignoreLoss,
            @DecimalMin("0.0") @DecimalMax("1.0") double repeatLoss,
            @DecimalMin("0.0") @DecimalMax("1.0") double reopenLoss,
            @Positive double halfLifeDays,
            @DecimalMin("0.0") @DecimalMax("1.0") double masteredThreshold
    ) {
    }

    /**
     * Alert-fatigue controls (Plan B). They change how a notice is delivered, never
     * whether it exists, and never touch exempt findings.
     */
    public record Fatigue(
            @Positive int interruptsPerHour,
            @Min(0) int cooldownMinutes,
            @Positive int quickDismissSeconds,
            @Positive int quickFixMinutes,
            @Positive int deEscalationQuickFixes,
            List<String> exemptCwes,
            List<Severity> exemptSeverities
    ) {
        public Fatigue {
            exemptCwes = exemptCwes == null ? List.of() : List.copyOf(exemptCwes);
            exemptSeverities = exemptSeverities == null ? List.of() : List.copyOf(exemptSeverities);
        }
    }

    /** A minimum level for findings matching a CWE and/or a severity. */
    public record LevelOverride(
            String cwe,
            Severity severity,
            @Min(1) @Max(4) int minLevel,
            String reason
    ) {
    }
}
