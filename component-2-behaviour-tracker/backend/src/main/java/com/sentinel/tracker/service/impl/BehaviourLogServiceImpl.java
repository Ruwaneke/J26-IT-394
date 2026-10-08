package com.sentinel.tracker.service.impl;

import com.sentinel.tracker.dto.BehaviourLogResponse;
import com.sentinel.tracker.dto.CreateBehaviourLogRequest;
import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.entity.Developer;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.entity.VulnerabilityLifecycleHistory;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.SecurityEventStatus;
import com.sentinel.tracker.exception.ResourceNotFoundException;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.repository.VulnerabilityLifecycleHistoryRepository;
import com.sentinel.tracker.service.BehaviourLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Implementation of {@link BehaviourLogService}.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class BehaviourLogServiceImpl implements BehaviourLogService {

    private final BehaviourLogRepository behaviourLogRepository;
    private final DeveloperRepository developerRepository;
    private final SecurityEventRepository securityEventRepository;
    private final VulnerabilityLifecycleHistoryRepository lifecycleHistoryRepository;

    @Override
    @Transactional
    public BehaviourLogResponse createBehaviourLog(CreateBehaviourLogRequest request) {
        log.info("Creating behaviour log for developer id: {}, action: {}",
                request.getDeveloperId(), request.getActionType());

        Developer developer = developerRepository.findById(request.getDeveloperId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Developer", "id", request.getDeveloperId()));

        SecurityEvent securityEvent = null;
        if (request.getSecurityEventId() != null) {
            securityEvent = securityEventRepository.findById(request.getSecurityEventId())
                    .orElseThrow(() -> new ResourceNotFoundException(
                            "Security event", "id", request.getSecurityEventId()));
        }

        LocalDateTime timestamp = request.getTimestamp() != null
                ? request.getTimestamp()
                : LocalDateTime.now();

        BehaviourLog log2 = BehaviourLog.builder()
                .developer(developer)
                .securityEvent(securityEvent)
                .actionType(request.getActionType())
                .timestamp(timestamp)
                .contextMetadata(request.getContextMetadata())
                .build();

        BehaviourLog saved = behaviourLogRepository.save(log2);
        log.info("BehaviourLog created with id: {}", saved.getId());
        return BehaviourLogResponse.from(saved);
    }

    @Override
    @Transactional
    public DeveloperInteractionResponse createInteraction(CreateDeveloperInteractionRequest request) {
        log.info("Creating developer interaction for security event id: {}, developer id: {}, action: {}",
                request.getSecurityEventId(), request.getDeveloperId(), request.getAction());

        Developer developer = developerRepository.findById(request.getDeveloperId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Developer", "id", request.getDeveloperId()));

        SecurityEvent securityEvent = securityEventRepository.findById(request.getSecurityEventId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Security event", "id", request.getSecurityEventId()));

        LocalDateTime actionTimestamp = request.getActionTimestamp() != null
                ? request.getActionTimestamp()
                : LocalDateTime.now();

        // Calculate timeSinceDetectionSeconds
        long timeSinceDetectionSeconds = ChronoUnit.SECONDS.between(securityEvent.getDetectedAt(), actionTimestamp);
        if (timeSinceDetectionSeconds < 0) {
            timeSinceDetectionSeconds = 0; // Safeguard for clock skew
        }

        BehaviourLog log2 = BehaviourLog.builder()
                .developer(developer)
                .securityEvent(securityEvent)
                .actionType(request.getAction())
                .timestamp(actionTimestamp)
                .timeSinceDetectionSeconds(timeSinceDetectionSeconds)
                .sessionId(request.getSessionId())
                .source(request.getSource())
                .contextMetadata(request.getMetadata())
                .build();

        BehaviourLog savedLog = behaviourLogRepository.save(log2);

        updateSecurityEventLifecycle(securityEvent, request.getAction(), developer.getDeveloperIdentifier(), actionTimestamp);

        return DeveloperInteractionResponse.from(savedLog);
    }

    private void updateSecurityEventLifecycle(SecurityEvent securityEvent, BehaviourAction action, String developerIdentifier, LocalDateTime actionTimestamp) {
        SecurityEventStatus newStatus = mapActionToStatus(action);
        if (newStatus != null && newStatus != securityEvent.getCurrentStatus()) {
            SecurityEventStatus previousStatus = securityEvent.getCurrentStatus();
            
            // Update the security event
            securityEvent.setCurrentStatus(newStatus);
            securityEventRepository.save(securityEvent);
            
            // Record the history
            VulnerabilityLifecycleHistory history = VulnerabilityLifecycleHistory.builder()
                    .securityEvent(securityEvent)
                    .previousStatus(previousStatus)
                    .newStatus(newStatus)
                    .changedAt(actionTimestamp)
                    .changedBy(developerIdentifier)
                    .build();
            lifecycleHistoryRepository.save(history);
            
            log.info("SecurityEvent id: {} transitioned from {} to {}", securityEvent.getId(), previousStatus, newStatus);
        }
    }

    private SecurityEventStatus mapActionToStatus(BehaviourAction action) {
        switch (action) {
            case OPEN: return SecurityEventStatus.OPENED;
            case IGNORE: return SecurityEventStatus.IGNORED;
            case FIX: return SecurityEventStatus.FIXED;
            case REOPEN: return SecurityEventStatus.REOPENED;
            case DISMISS: return SecurityEventStatus.IGNORED;
            default: return null;
        }
    }

    @Override
    public BehaviourLogResponse getBehaviourLogById(Long id) {
        BehaviourLog bl = behaviourLogRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Behaviour log", "id", id));
        return BehaviourLogResponse.from(bl);
    }

    @Override
    public List<BehaviourLogResponse> getBehaviourLogsByDeveloper(Long developerId) {
        if (!developerRepository.existsById(developerId)) {
            throw new ResourceNotFoundException("Developer", "id", developerId);
        }
        return behaviourLogRepository.findByDeveloperId(developerId).stream()
                .map(BehaviourLogResponse::from)
                .collect(Collectors.toList());
    }

    @Override
    public List<BehaviourLogResponse> getAllBehaviourLogs() {
        return behaviourLogRepository.findAll().stream()
                .map(BehaviourLogResponse::from)
                .collect(Collectors.toList());
    }

    // ── Phase 03 Interaction Retrieval ────────────────────────────────────────

    @Override
    public DeveloperInteractionResponse getInteractionById(Long id) {
        BehaviourLog bl = behaviourLogRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Developer interaction", "id", id));
        return DeveloperInteractionResponse.from(bl);
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
}
