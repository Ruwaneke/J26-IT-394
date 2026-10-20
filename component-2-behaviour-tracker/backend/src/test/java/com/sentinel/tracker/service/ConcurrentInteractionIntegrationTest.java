package com.sentinel.tracker.service;

import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.CreateSecurityEventRequest;
import com.sentinel.tracker.dto.HistoryVerificationResponse;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.HistoryIntegrityStatus;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.enums.Severity;
import com.sentinel.tracker.exception.DuplicateResourceException;
import com.sentinel.tracker.exception.InvalidStatusTransitionException;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.repository.VulnerabilityLifecycleHistoryRepository;
import com.sentinel.tracker.dto.CreateDeveloperRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Concurrent writes on one security event (TASKS P1-5). The pessimistic row lock in
 * {@code DeveloperInteractionServiceImpl} must serialise them, so the status, the history and
 * the hash chain stay consistent whatever order the threads run in.
 *
 * <p>Uses its own H2 database with a 10 s lock timeout, so waiting threads queue instead of
 * failing.
 */
@SpringBootTest
@ActiveProfiles("test")
@TestPropertySource(properties =
        "spring.datasource.url=jdbc:h2:mem:concurrencydb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE;LOCK_TIMEOUT=10000")
class ConcurrentInteractionIntegrationTest {

    private static final int THREADS = 8;

    @Autowired
    private DeveloperInteractionService interactionService;

    @Autowired
    private SecurityEventService securityEventService;

    @Autowired
    private DeveloperService developerService;

    @Autowired
    private VulnerabilityLifecycleHistoryService historyService;

    @Autowired
    private DeveloperRepository developerRepository;

    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Autowired
    private BehaviourLogRepository behaviourLogRepository;

    @Autowired
    private VulnerabilityLifecycleHistoryRepository lifecycleHistoryRepository;

    private Long developerId;

    @BeforeEach
    void setUp() {
        developerId = developerRepository.save(
                Developer.builder().developerIdentifier("concurrency-dev").build()).getId();
    }

    @AfterEach
    void tearDown() {
        lifecycleHistoryRepository.deleteAll();
        behaviourLogRepository.deleteAll();
        securityEventRepository.deleteAll();
        developerRepository.deleteAll();
    }

    @Test
    void concurrentOpens_shouldAllBeLoggedWithExactlyOneTransition() throws Exception {
        Long eventId = createEvent();

        List<Outcome> outcomes = runConcurrently(eventId, List.of(
                BehaviourAction.OPEN, BehaviourAction.OPEN, BehaviourAction.OPEN, BehaviourAction.OPEN,
                BehaviourAction.OPEN, BehaviourAction.OPEN, BehaviourAction.OPEN, BehaviourAction.OPEN));

        assertThat(outcomes).allMatch(o -> o == Outcome.ACCEPTED);
        assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize(THREADS);
        // Without the lock, two threads could both see DETECTED and both write DETECTED -> OPENED
        assertThat(history(eventId)).extracting(VulnerabilityLifecycleHistory::getNewStatus)
                .containsExactly(SecurityEventStatus.DETECTED, SecurityEventStatus.OPENED);
        assertConsistent(eventId, outcomes);
    }

    @RepeatedTest(3)
    void concurrentMixedActions_shouldLeaveStatusHistoryAndChainConsistent() throws Exception {
        Long eventId = createEvent();

        List<Outcome> outcomes = runConcurrently(eventId, List.of(
                BehaviourAction.OPEN, BehaviourAction.FIX, BehaviourAction.IGNORE, BehaviourAction.REOPEN,
                BehaviourAction.OPEN, BehaviourAction.DISMISS, BehaviourAction.FIX, BehaviourAction.REOPEN));

        assertConsistent(eventId, outcomes);
    }

    @Test
    void concurrentDuplicateDeveloperCreation_shouldStoreOneDeveloper() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> results = new ArrayList<>();
        for (int i = 0; i < THREADS; i++) {
            results.add(pool.submit(() -> {
                start.await();
                CreateDeveloperRequest request = new CreateDeveloperRequest();
                request.setDeveloperIdentifier("concurrency-duplicate");
                try {
                    developerService.createDeveloper(request);
                    return true;
                } catch (DuplicateResourceException | org.springframework.dao.DataIntegrityViolationException e) {
                    // Either the existence check or the unique constraint stops the duplicate
                    return false;
                }
            }));
        }
        start.countDown();
        int created = 0;
        for (Future<Boolean> result : results) {
            if (result.get(30, TimeUnit.SECONDS)) {
                created++;
            }
        }
        pool.shutdown();

        assertThat(created).isEqualTo(1);
        assertThat(developerRepository.findByDeveloperIdentifier("concurrency-duplicate")).isPresent();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private enum Outcome { ACCEPTED, REJECTED }

    private Long createEvent() {
        CreateSecurityEventRequest request = new CreateSecurityEventRequest();
        request.setDeveloperId(developerId);
        request.setVulnerabilityType("SQL_INJECTION");
        request.setSeverity(Severity.HIGH);
        request.setFileName("UserDao.java");
        request.setLineNumber(42);
        request.setMessage("Unparameterised query");
        return securityEventService.createSecurityEvent(request).getId();
    }

    /** Sends every action at once from its own thread; a 409 counts as REJECTED, anything else fails. */
    private List<Outcome> runConcurrently(Long eventId, List<BehaviourAction> actions) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(actions.size());
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Outcome>> futures = new ArrayList<>();
        for (BehaviourAction action : actions) {
            Callable<Outcome> task = () -> {
                start.await();
                CreateDeveloperInteractionRequest request = new CreateDeveloperInteractionRequest();
                request.setDeveloperId(developerId);
                request.setSecurityEventId(eventId);
                request.setAction(action);
                request.setSessionId("SESSION-CONCURRENT");
                try {
                    interactionService.createInteraction(request);
                    return Outcome.ACCEPTED;
                } catch (InvalidStatusTransitionException e) {
                    return Outcome.REJECTED;
                }
            };
            futures.add(pool.submit(task));
        }
        start.countDown();
        List<Outcome> outcomes = new ArrayList<>();
        for (Future<Outcome> future : futures) {
            outcomes.add(future.get(60, TimeUnit.SECONDS));
        }
        pool.shutdown();
        return outcomes;
    }

    /**
     * Invariants that hold for every interleaving: one log per accepted action, a history that
     * is a valid path through the lifecycle and ends at the current status, and a valid chain.
     */
    private void assertConsistent(Long eventId, List<Outcome> outcomes) {
        long accepted = outcomes.stream().filter(o -> o == Outcome.ACCEPTED).count();
        assertThat(behaviourLogRepository.findBySecurityEventId(eventId)).hasSize((int) accepted);

        List<VulnerabilityLifecycleHistory> history = history(eventId);
        assertThat(history.get(0).getNewStatus()).isEqualTo(SecurityEventStatus.DETECTED);
        for (int i = 1; i < history.size(); i++) {
            VulnerabilityLifecycleHistory entry = history.get(i);
            assertThat(entry.getPreviousStatus()).isEqualTo(history.get(i - 1).getNewStatus());
            assertThat(entry.getPreviousStatus().canTransitionTo(entry.getNewStatus()))
                    .as("history entry %d: %s -> %s", i + 1, entry.getPreviousStatus(), entry.getNewStatus())
                    .isTrue();
            assertThat(entry.getPrevHash()).isEqualTo(history.get(i - 1).getEntryHash());
        }
        assertThat(securityEventRepository.findById(eventId).orElseThrow().getCurrentStatus())
                .isEqualTo(history.get(history.size() - 1).getNewStatus());

        HistoryVerificationResponse verification = historyService.verifyHistory(eventId);
        assertThat(verification.getStatus()).isEqualTo(HistoryIntegrityStatus.VALID);
    }

    private List<VulnerabilityLifecycleHistory> history(Long eventId) {
        return lifecycleHistoryRepository.findBySecurityEventIdOrderByIdAsc(eventId);
    }
}
