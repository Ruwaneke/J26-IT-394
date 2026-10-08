package com.sentinel.tracker.repository;

import com.sentinel.tracker.config.JpaAuditingConfig;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

/**
 * Phase 02 – Repository integration tests for {@link SecurityEventRepository}.
 *
 * Uses @DataJpaTest with H2 in-memory database to verify:
 * - Persistence of all SecurityEvent fields
 * - FK relationship to Developer
 * - Custom query methods
 * - Default DETECTED status
 */
@DataJpaTest
@ActiveProfiles("test")
@Import(JpaAuditingConfig.class)
class SecurityEventRepositoryPhase02Test {

    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Autowired
    private DeveloperRepository developerRepository;

    private Developer developer;

    @BeforeEach
    void setUp() {
        developer = developerRepository.save(
                Developer.builder().developerIdentifier("phase02-dev").build());
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("save – should persist all SecurityEvent fields to database")
    void save_shouldPersistAllFields() {
        LocalDateTime detectedAt = LocalDateTime.of(2026, 8, 10, 14, 0, 0);

        SecurityEvent event = SecurityEvent.builder()
                .developer(developer)
                .vulnerabilityType("SQL_INJECTION")
                .severity(Severity.HIGH)
                .fileName("UserService.java")
                .lineNumber(45)
                .message("Possible SQL injection vulnerability")
                .detectedAt(detectedAt)
                .build();

        SecurityEvent saved = securityEventRepository.save(event);

        assertThat(saved.getId()).isNotNull();
        assertThat(saved.getVulnerabilityType()).isEqualTo("SQL_INJECTION");
        assertThat(saved.getSeverity()).isEqualTo(Severity.HIGH);
        assertThat(saved.getFileName()).isEqualTo("UserService.java");
        assertThat(saved.getLineNumber()).isEqualTo(45);
        assertThat(saved.getMessage()).isEqualTo("Possible SQL injection vulnerability");
        assertThat(saved.getDetectedAt()).isEqualTo(detectedAt);
        assertThat(saved.getCurrentStatus()).isEqualTo(SecurityEventStatus.DETECTED);
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(saved.getUpdatedAt()).isNotNull();
        assertThat(saved.getDeveloper().getId()).isEqualTo(developer.getId());
    }

    @Test
    @DisplayName("save – default currentStatus should be DETECTED when not explicitly set")
    void save_defaultStatusShouldBeDetected() {
        SecurityEvent event = SecurityEvent.builder()
                .developer(developer)
                .vulnerabilityType("XSS")
                .severity(Severity.MEDIUM)
                .fileName("template.html")
                .lineNumber(10)
                .message("XSS vulnerability detected")
                .detectedAt(LocalDateTime.now())
                .build();

        SecurityEvent saved = securityEventRepository.save(event);

        assertThat(saved.getCurrentStatus()).isEqualTo(SecurityEventStatus.DETECTED);
    }

    @Test
    @DisplayName("findById – should retrieve persisted event by ID")
    void findById_shouldReturnPersistedEvent() {
        SecurityEvent saved = securityEventRepository.save(buildEvent("CSRF", Severity.LOW));

        Optional<SecurityEvent> found = securityEventRepository.findById(saved.getId());

        assertThat(found).isPresent();
        assertThat(found.get().getVulnerabilityType()).isEqualTo("CSRF");
    }

    // ── Custom query methods ──────────────────────────────────────────────────

    @Test
    @DisplayName("findByDeveloperId – should return only events for that developer")
    void findByDeveloperId_shouldReturnDeveloperEvents() {
        // Save events for our developer
        securityEventRepository.save(buildEvent("SQL_INJECTION", Severity.HIGH));
        securityEventRepository.save(buildEvent("XSS", Severity.MEDIUM));

        // Save event for a different developer
        Developer otherDev = developerRepository.save(
                Developer.builder().developerIdentifier("other-dev").build());
        SecurityEvent otherEvent = SecurityEvent.builder()
                .developer(otherDev)
                .vulnerabilityType("CSRF")
                .severity(Severity.LOW)
                .fileName("form.html")
                .lineNumber(1)
                .message("CSRF token missing")
                .detectedAt(LocalDateTime.now())
                .build();
        securityEventRepository.save(otherEvent);

        List<SecurityEvent> events = securityEventRepository.findByDeveloperId(developer.getId());

        assertThat(events).hasSize(2);
        assertThat(events).allMatch(e -> e.getDeveloper().getId().equals(developer.getId()));
    }

    @Test
    @DisplayName("findByDeveloperIdAndSeverity – should filter by severity")
    void findByDeveloperIdAndSeverity_shouldFilterCorrectly() {
        securityEventRepository.save(buildEvent("SQL_INJECTION", Severity.HIGH));
        securityEventRepository.save(buildEvent("XSS", Severity.HIGH));
        securityEventRepository.save(buildEvent("CSRF", Severity.LOW));

        List<SecurityEvent> highSeverity = securityEventRepository
                .findByDeveloperIdAndSeverity(developer.getId(), Severity.HIGH);

        assertThat(highSeverity).hasSize(2);
        assertThat(highSeverity).allMatch(e -> e.getSeverity() == Severity.HIGH);
    }

    @Test
    @DisplayName("findByDeveloperIdAndCurrentStatus – should filter by status")
    void findByDeveloperIdAndCurrentStatus_shouldFilterCorrectly() {
        securityEventRepository.save(buildEvent("SQL_INJECTION", Severity.HIGH));
        // All saved events will have DETECTED status by default
        List<SecurityEvent> detected = securityEventRepository
                .findByDeveloperIdAndCurrentStatus(developer.getId(), SecurityEventStatus.DETECTED);

        assertThat(detected).hasSize(1);
        assertThat(detected.get(0).getCurrentStatus()).isEqualTo(SecurityEventStatus.DETECTED);
    }

    @Test
    @DisplayName("findByVulnerabilityType – should find events by type")
    void findByVulnerabilityType_shouldReturnMatchingEvents() {
        securityEventRepository.save(buildEvent("SQL_INJECTION", Severity.HIGH));
        securityEventRepository.save(buildEvent("SQL_INJECTION", Severity.CRITICAL));
        securityEventRepository.save(buildEvent("XSS", Severity.LOW));

        List<SecurityEvent> sqlEvents = securityEventRepository.findByVulnerabilityType("SQL_INJECTION");

        assertThat(sqlEvents).hasSize(2);
        assertThat(sqlEvents).allMatch(e -> e.getVulnerabilityType().equals("SQL_INJECTION"));
    }

    @Test
    @DisplayName("countByDeveloperIdAndCurrentStatus – should count correctly")
    void countByDeveloperIdAndCurrentStatus_shouldReturnCorrectCount() {
        securityEventRepository.save(buildEvent("SQL_INJECTION", Severity.HIGH));
        securityEventRepository.save(buildEvent("XSS", Severity.MEDIUM));

        long count = securityEventRepository.countByDeveloperIdAndCurrentStatus(
                developer.getId(), SecurityEventStatus.DETECTED);

        assertThat(count).isEqualTo(2);
    }

    @Test
    @DisplayName("save – should store all four severity levels correctly")
    void save_shouldStorAllSeverityLevels() {
        for (Severity severity : Severity.values()) {
            SecurityEvent event = buildEvent("VULN_" + severity.name(), severity);
            SecurityEvent saved = securityEventRepository.save(event);
            assertThat(saved.getSeverity()).isEqualTo(severity);
        }

        List<SecurityEvent> allEvents = securityEventRepository.findByDeveloperId(developer.getId());
        assertThat(allEvents).hasSize(Severity.values().length);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private SecurityEvent buildEvent(String type, Severity severity) {
        return SecurityEvent.builder()
                .developer(developer)
                .vulnerabilityType(type)
                .severity(severity)
                .fileName("File.java")
                .lineNumber(10)
                .message("Vulnerability: " + type)
                .detectedAt(LocalDateTime.now())
                .build();
    }
}
