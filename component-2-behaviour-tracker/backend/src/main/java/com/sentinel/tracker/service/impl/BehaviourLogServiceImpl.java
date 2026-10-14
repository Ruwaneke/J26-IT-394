package com.sentinel.tracker.service.impl;

import com.sentinel.tracker.dto.BehaviourLogResponse;
import com.sentinel.tracker.dto.CreateBehaviourLogRequest;
import com.sentinel.tracker.dto.CreateDeveloperInteractionRequest;
import com.sentinel.tracker.dto.DeveloperInteractionResponse;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.exception.ResourceNotFoundException;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.service.BehaviourLogService;
import com.sentinel.tracker.service.DeveloperInteractionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Implementation of {@link BehaviourLogService}.
 *
 * Read-only access to behaviour logs, plus the deprecated create operation, which
 * delegates to {@link DeveloperInteractionService} so that both APIs share the
 * same lifecycle logic.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class BehaviourLogServiceImpl implements BehaviourLogService {

    private final BehaviourLogRepository behaviourLogRepository;
    private final DeveloperRepository developerRepository;
    private final DeveloperInteractionService developerInteractionService;

    @Override
    @Deprecated
    @Transactional
    public BehaviourLogResponse createBehaviourLog(CreateBehaviourLogRequest request) {
        log.warn("Deprecated POST /api/behaviour-logs used (developer id: {}, action: {}); "
                + "use POST /api/developer-interactions instead",
                request.getDeveloperId(), request.getActionType());

        CreateDeveloperInteractionRequest interaction = new CreateDeveloperInteractionRequest();
        interaction.setDeveloperId(request.getDeveloperId());
        interaction.setSecurityEventId(request.getSecurityEventId());
        interaction.setAction(request.getActionType());
        interaction.setActionTimestamp(request.getTimestamp());
        interaction.setMetadata(request.getContextMetadata());

        DeveloperInteractionResponse created = developerInteractionService.createInteraction(interaction);
        return BehaviourLogResponse.from(created);
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
}
