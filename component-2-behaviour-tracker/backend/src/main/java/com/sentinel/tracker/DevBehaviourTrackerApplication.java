package com.sentinel.tracker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Developer Behaviour Tracking Module backend.
 *
 * Phase 01: Database & Spring Boot Backend Foundation
 * Phase 02: Security Event Collection
 *
 * Note: JPA Auditing is enabled via {@link com.sentinel.tracker.config.JpaAuditingConfig}.
 */
@SpringBootApplication
public class DevBehaviourTrackerApplication {

    public static void main(String[] args) {
        SpringApplication.run(DevBehaviourTrackerApplication.class, args);
    }
}
