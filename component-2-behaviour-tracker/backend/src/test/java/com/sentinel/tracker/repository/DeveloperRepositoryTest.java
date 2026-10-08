package com.sentinel.tracker.repository;

import com.sentinel.tracker.config.JpaAuditingConfig;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
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
 * Integration tests for JPA repositories using H2 in-memory database.
 *
 * @DataJpaTest loads only the JPA slice – no web layer or service beans.
 */
@DataJpaTest
@ActiveProfiles("test")
@Import(JpaAuditingConfig.class)
class DeveloperRepositoryTest {

    @Autowired
    private DeveloperRepository developerRepository;

    @Autowired
    private SecurityEventRepository securityEventRepository;

    // ── Developer tests ───────────────────────────────────────────────────────

    @Test
    @DisplayName("save and findById – should persist and retrieve Developer")
    void saveDeveloper_shouldPersistCorrectly() {
        Developer developer = Developer.builder()
                .developerIdentifier("test-dev-001")
                .build();

        Developer saved = developerRepository.save(developer);

        assertThat(saved.getId()).isNotNull();
        assertThat(saved.getDeveloperIdentifier()).isEqualTo("test-dev-001");

        Optional<Developer> found = developerRepository.findById(saved.getId());
        assertThat(found).isPresent();
        assertThat(found.get().getDeveloperIdentifier()).isEqualTo("test-dev-001");
    }

    @Test
    @DisplayName("findByDeveloperIdentifier – should find developer by identifier")
    void findByDeveloperIdentifier_shouldReturnDeveloper() {
        Developer developer = Developer.builder()
                .developerIdentifier("unique-identifier-123")
                .build();
        developerRepository.save(developer);

        Optional<Developer> found = developerRepository.findByDeveloperIdentifier("unique-identifier-123");

        assertThat(found).isPresent();
        assertThat(found.get().getDeveloperIdentifier()).isEqualTo("unique-identifier-123");
    }

    @Test
    @DisplayName("existsByDeveloperIdentifier – should return true when identifier exists")
    void existsByDeveloperIdentifier_shouldReturnTrue() {
        Developer developer = Developer.builder()
                .developerIdentifier("existing-dev")
                .build();
        developerRepository.save(developer);

        boolean exists = developerRepository.existsByDeveloperIdentifier("existing-dev");

        assertThat(exists).isTrue();
    }

    @Test
    @DisplayName("existsByDeveloperIdentifier – should return false when identifier does not exist")
    void existsByDeveloperIdentifier_shouldReturnFalse() {
        boolean exists = developerRepository.existsByDeveloperIdentifier("non-existing-dev");

        assertThat(exists).isFalse();
    }

    // ── SecurityEvent tests ───────────────────────────────────────────────────

    @Test
    @DisplayName("findByDeveloperId – should return events for a specific developer")
    void findByDeveloperId_shouldReturnSecurityEvents() {
        Developer developer = developerRepository.save(
                Developer.builder().developerIdentifier("dev-for-events").build());

        SecurityEvent event = SecurityEvent.builder()
                .developer(developer)
                .vulnerabilityType("XSS")
                .severity(Severity.MEDIUM)
                .fileName("template.html")
                .lineNumber(20)
                .message("XSS vulnerability detected")
                .detectedAt(LocalDateTime.now())
                .currentStatus(SecurityEventStatus.DETECTED)
                .build();

        securityEventRepository.save(event);

        List<SecurityEvent> events = securityEventRepository.findByDeveloperId(developer.getId());

        assertThat(events).hasSize(1);
        assertThat(events.get(0).getVulnerabilityType()).isEqualTo("XSS");
        assertThat(events.get(0).getCurrentStatus()).isEqualTo(SecurityEventStatus.DETECTED);
    }

    @Test
    @DisplayName("SecurityEvent – default status should be DETECTED")
    void securityEvent_defaultStatusShouldBeDetected() {
        Developer developer = developerRepository.save(
                Developer.builder().developerIdentifier("dev-status-test").build());

        SecurityEvent event = SecurityEvent.builder()
                .developer(developer)
                .vulnerabilityType("CSRF")
                .severity(Severity.LOW)
                .fileName("form.html")
                .lineNumber(5)
                .message("Missing CSRF token")
                .detectedAt(LocalDateTime.now())
                .build();

        SecurityEvent saved = securityEventRepository.save(event);

        assertThat(saved.getCurrentStatus()).isEqualTo(SecurityEventStatus.DETECTED);
    }
}
