package com.sentinel.tracker.service.impl;

import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.exception.AccessDeniedException;
import com.sentinel.tracker.exception.InvalidStatusTransitionException;
import com.sentinel.tracker.exception.ResourceNotFoundException;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.repository.VulnerabilityLifecycleHistoryRepository;
import com.sentinel.tracker.service.DeveloperInteractionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Implementation of {@link DeveloperInteractionService}.
 *
 * <p>Creating an interaction:
 * <ol>
 *   <li>Loads and validates the developer and security event.</li>
 *   <li>Checks the developer owns the security event (owner check).</li>
 *   <li>Resolves the target {@link SecurityEventStatus} from the {@link BehaviourAction}.</li>
 *   <li>Validates the lifecycle transition against {@link SecurityEventStatus#canTransitionTo}.</li>
 *   <li>Persists the {@link BehaviourLog} with {@code timeSinceDetectionSeconds}.</li>
 *   <li>Updates the {@link SecurityEvent#currentStatus}.</li>
 *   <li>Appends a {@link VulnerabilityLifecycleHistory} entry.</li>
 * </ol>
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class DeveloperInteractionServiceImpl implements DeveloperInteractionService {

    private final BehaviourLogRepository behaviourLogRepository;
    private final DeveloperRepository developerRepository;
    private final SecurityEventRepository securityEventRepository;
    private final VulnerabilityLifecycleHistoryRepository lifecycleHistoryRepository;

    @Override
    @Transactional
    public DeveloperInteractionResponse createInteraction(CreateDeveloperInteractionRequest request) {
        log.info("Creating developer interaction: developerId={}, securityEventId={}, action={}",
                request.getDeveloperId(), request.getSecurityEventId(), request.getAction());

        // 1. Load developer
        Developer developer = developerRepository.findById(request.getDeveloperId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Developer", "id", request.getDeveloperId()));

        // 2. Load security event with a pessimistic write lock to serialise concurrent interactions
        SecurityEvent event = securityEventRepository.findByIdForUpdate(request.getSecurityEventId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Security event", "id", request.getSecurityEventId()));

        // 3. Ownership check – the interacting developer must own the security event
        if (!event.getDeveloper().getId().equals(developer.getId())) {
            throw new AccessDeniedException(
                    String.format("Developer %d is not allowed to act on security event %d",
                            developer.getId(), event.getId()));
        }

        // 4. Resolve target status from action
        SecurityEventStatus targetStatus = resolveTargetStatus(request.getAction());

        // 5. Validate lifecycle transition
        SecurityEventStatus currentStatus = event.getCurrentStatus();
        if (!currentStatus.canTransitionTo(targetStatus)) {
            throw new InvalidStatusTransitionException(
                    String.format("Security event %d cannot move from %s to %s (action %s); "
                                    + "allowed next statuses: %s",
                            event.getId(),
                            currentStatus,
                            targetStatus,
                            request.getAction(),
                            currentStatus.allowedTransitions()));
        }

        // 6. Compute time since detection
        LocalDateTime actionTimestamp = request.getActionTimestamp() != null
                ? request.getActionTimestamp()
                : LocalDateTime.now();
        long timeSinceDetectionSeconds = ChronoUnit.SECONDS.between(event.getDetectedAt(), actionTimestamp);

        // 7. Persist BehaviourLog
        BehaviourLog log = BehaviourLog.builder()
                .developer(developer)
                .securityEvent(event)
                .actionType(request.getAction())
                .timestamp(actionTimestamp)
                .contextMetadata(request.getMetadata())
                .timeSinceDetectionSeconds(timeSinceDetectionSeconds)
                .sessionId(request.getSessionId())
                .source(request.getSource())
                .build();
        BehaviourLog saved = behaviourLogRepository.save(log);

        // 8. Update security event status
        event.setCurrentStatus(targetStatus);
        securityEventRepository.save(event);

        // 9. Append lifecycle history entry
        VulnerabilityLifecycleHistory history = VulnerabilityLifecycleHistory.builder()
                .securityEvent(event)
                .previousStatus(currentStatus)
                .newStatus(targetStatus)
                .changedAt(actionTimestamp)
                .changedBy(developer.getDeveloperIdentifier() != null
                        ? developer.getDeveloperIdentifier()
                        : String.valueOf(developer.getId()))
                .build();
        lifecycleHistoryRepository.save(history);

        this.log.info("Developer interaction created with id: {}", saved.getId());
        return DeveloperInteractionResponse.from(saved);
    }

    @Override
    public DeveloperInteractionResponse getInteractionById(Long id) {
        BehaviourLog log = behaviourLogRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Developer interaction", "id", id));
        return DeveloperInteractionResponse.from(log);
    }

    @Override
    public List<DeveloperInteractionResponse> getAllInteractions() {
        return behaviourLogRepository.findAll().stream()
                .map(DeveloperInteractionResponse::from)
                .collect(Collectors.toList());
    }

    @Override
    public List<DeveloperInteractionResponse> getInteractionsByDeveloper(Long developerId) {
        if (!developerRepository.existsById(developerId)) {
            throw new ResourceNotFoundException("Developer", "id", developerId);
        }
        return behaviourLogRepository.findByDeveloperId(developerId).stream()
                .map(DeveloperInteractionResponse::from)
                .collect(Collectors.toList());
    }

    @Override
    public List<DeveloperInteractionResponse> getInteractionsBySecurityEvent(Long securityEventId) {
        if (!securityEventRepository.existsById(securityEventId)) {
            throw new ResourceNotFoundException("Security event", "id", securityEventId);
        }
        return behaviourLogRepository.findBySecurityEventId(securityEventId).stream()
                .map(DeveloperInteractionResponse::from)
                .collect(Collectors.toList());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Maps a {@link BehaviourAction} to the resulting {@link SecurityEventStatus}.
     *
     * <ul>
     *   <li>OPEN   → OPENED</li>
     *   <li>FIX    → FIXED</li>
     *   <li>IGNORE → IGNORED</li>
     *   <li>REOPEN → REOPENED</li>
     *   <li>DISMISS → IGNORED (treated the same as IGNORE for lifecycle purposes)</li>
     * </ul>
     */
    private SecurityEventStatus resolveTargetStatus(BehaviourAction action) {
        return switch (action) {
            case OPEN    -> SecurityEventStatus.OPENED;
            case FIX     -> SecurityEventStatus.FIXED;
            case IGNORE  -> SecurityEventStatus.IGNORED;
            case REOPEN  -> SecurityEventStatus.REOPENED;
            case DISMISS -> SecurityEventStatus.IGNORED;
        };
    }
}
