package com.sentinel.tracker.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * Enables JPA Auditing so that {@code @CreatedDate} and {@code @LastModifiedDate}
 * fields on entities are automatically populated by Spring Data.
 *
 * This configuration is imported explicitly in {@code @DataJpaTest} slices
 * (which do not load the full application context) via {@code @Import(JpaAuditingConfig.class)}.
 */
@Configuration
@EnableJpaAuditing
public class JpaAuditingConfig {
}
