package com.sentinel.feedback.policy;

import com.sentinel.feedback.model.Severity;

import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;

/** Policies for tests that run without a Spring context. */
public final class TestPolicies {

    private TestPolicies() {
    }

    /** The plan's starting values (policy 1.0.0); unit tests pin their numbers to these. */
    public static PolicyProperties defaults() {
        return new PolicyProperties(
                "1.0.0",
                new PolicyProperties.Weights(35, 20, 20, 15, 10),
                3,
                false,
                new PolicyProperties.Recency(7, 14),
                new PolicyProperties.Levels(30, 55, 80),
                new PolicyProperties.Mastery(0.5, 0.25, 0.15, 0.30, 0.20, 30, 0.75),
                List.of(
                        new PolicyProperties.LevelOverride("CWE-798", null, 3, "secret floor"),
                        new PolicyProperties.LevelOverride(null, Severity.CRITICAL, 2,
                                "critical floor")),
                new PolicyProperties.Fatigue(3, 10, 2, 10, 3, List.of("CWE-798"),
                        List.of(Severity.CRITICAL)));
    }

    /** The policy actually shipped in src/main/resources/policy.yaml. */
    public static PolicyProperties shipped() {
        try {
            var sources = new YamlPropertySourceLoader()
                    .load("policy", new ClassPathResource("policy.yaml"));
            return new Binder(ConfigurationPropertySources.from(sources))
                    .bind("policy", PolicyProperties.class)
                    .get();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
