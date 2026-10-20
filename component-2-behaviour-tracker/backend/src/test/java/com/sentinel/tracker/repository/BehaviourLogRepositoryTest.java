package com.sentinel.tracker.repository;

import com.sentinel.tracker.config.JpaAuditingConfig;
import com.sentinel.tracker.dto.BehaviourLogResponse;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.Severity;
import jakarta.persistence.PersistenceUnitUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the {@code @EntityGraph} reads of {@link BehaviourLogRepository} load the
 * developer and security event, so the results can be mapped to response DTOs after the
 * persistence context is gone ({@code open-in-view=false}).
 *
 * Each test clears the persistence context before reading, so nothing is served from the
 * first-level cache and every relation must come from the query itself.
 */
@DataJpaTest
@ActiveProfiles("test")
@Import(JpaAuditingConfig.class)
class BehaviourLogRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private BehaviourLogRepository behaviourLogRepository;

    private PersistenceUnitUtil persistenceUnitUtil;
    private Developer developer;
    private SecurityEvent event;
    private BehaviourLog savedLog;

    @BeforeEach
    void setUp() {
        persistenceUnitUtil = entityManager.getEntityManager()
                .getEntityManagerFactory().getPersistenceUnitUtil();

        developer = entityManager.persist(Developer.builder().developerIdentifier("graph-dev").build());
        event = entityManager.persist(SecurityEvent.builder()
                .developer(developer)
                .vulnerabilityType("SQL_INJECTION")
                .severity(Severity.HIGH)
                .fileName("UserDao.java")
                .lineNumber(42)
                .message("Unparameterised query")
                .detectedAt(LocalDateTime.now().minusMinutes(5))
                .build());
        savedLog = entityManager.persist(BehaviourLog.builder()
                .developer(developer)
                .securityEvent(event)
                .actionType(BehaviourAction.OPEN)
                .timestamp(LocalDateTime.now())
                .timeSinceDetectionSeconds(300L)
                .build());
        entityManager.flush();
        entityManager.clear();
    }

    @Test
    @DisplayName("findById – loads developer and security event")
    void findById_shouldFetchRelations() {
        BehaviourLog found = behaviourLogRepository.findById(savedLog.getId()).orElseThrow();

        assertRelationsLoadedAndMappable(found);
    }

    @Test
    @DisplayName("findByDeveloperId – loads developer and security event")
    void findByDeveloperId_shouldFetchRelations() {
        List<BehaviourLog> found = behaviourLogRepository.findByDeveloperId(developer.getId());

        assertThat(found).hasSize(1);
        assertRelationsLoadedAndMappable(found.get(0));
    }

    @Test
    @DisplayName("findBySecurityEventId – loads developer and security event")
    void findBySecurityEventId_shouldFetchRelations() {
        List<BehaviourLog> found = behaviourLogRepository.findBySecurityEventId(event.getId());

        assertThat(found).hasSize(1);
        assertRelationsLoadedAndMappable(found.get(0));
    }

    @Test
    @DisplayName("findByDeveloperIdAndActionType – loads developer and security event")
    void findByDeveloperIdAndActionType_shouldFetchRelations() {
        List<BehaviourLog> found = behaviourLogRepository
                .findByDeveloperIdAndActionType(developer.getId(), BehaviourAction.OPEN);

        assertThat(found).hasSize(1);
        assertRelationsLoadedAndMappable(found.get(0));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void assertRelationsLoadedAndMappable(BehaviourLog log) {
        assertThat(persistenceUnitUtil.isLoaded(log, "developer")).isTrue();
        assertThat(persistenceUnitUtil.isLoaded(log, "securityEvent")).isTrue();
        assertThat(persistenceUnitUtil.isLoaded(log.getDeveloper())).isTrue();
        assertThat(persistenceUnitUtil.isLoaded(log.getSecurityEvent())).isTrue();

        // Detach, as after a service method returns, then map as the controllers do
        entityManager.clear();

        BehaviourLogResponse logResponse = BehaviourLogResponse.from(log);
        assertThat(logResponse.getDeveloperId()).isEqualTo(developer.getId());
        assertThat(logResponse.getSecurityEventId()).isEqualTo(event.getId());

        DeveloperInteractionResponse interactionResponse = DeveloperInteractionResponse.from(log);
        assertThat(interactionResponse.getDeveloperId()).isEqualTo(developer.getId());
        assertThat(interactionResponse.getSecurityEventId()).isEqualTo(event.getId());
        assertThat(interactionResponse.getAction()).isEqualTo(BehaviourAction.OPEN);
    }
}
