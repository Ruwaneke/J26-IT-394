package com.sentinel.tracker.service.impl;

import com.sentinel.tracker.analysis.ResponseSequenceAnalysis;
import com.sentinel.tracker.analysis.ResponseSequenceAnalysis.ActionRecord;
import com.sentinel.tracker.dto.ResponseSequenceAnalysisResponse;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.exception.ResourceNotFoundException;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.service.ResponseSequenceService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Implementation of {@link ResponseSequenceService}.
 *
 * Reads the developer's own security events and behaviour logs (the developer actions) and
 * hands them to {@link ResponseSequenceAnalysis}. Lifecycle history is not read, so the
 * SYSTEM-written DETECTED entry and the history copies of each action are never counted.
 * Read-only: nothing is stored.
 */
@Service
@Slf4j
@Transactional(readOnly = true)
public class ResponseSequenceServiceImpl implements ResponseSequenceService {

    private final DeveloperRepository developerRepository;
    private final SecurityEventRepository securityEventRepository;
    private final BehaviourLogRepository behaviourLogRepository;
    private final ResponseSequenceAnalysis.Thresholds thresholds;

    public ResponseSequenceServiceImpl(
            DeveloperRepository developerRepository,
            SecurityEventRepository securityEventRepository,
            BehaviourLogRepository behaviourLogRepository,
            @Value("${sequence-analysis.min-sequences:3}") int minSequences,
            @Value("${sequence-analysis.min-pattern-sequences:2}") int minPatternSequences,
            @Value("${sequence-analysis.min-support-percent:10}") double minSupportPercent,
            @Value("${sequence-analysis.min-transition-sample:5}") int minTransitionSample) {
        this.developerRepository = developerRepository;
        this.securityEventRepository = securityEventRepository;
        this.behaviourLogRepository = behaviourLogRepository;
        this.thresholds = new ResponseSequenceAnalysis.Thresholds(
                minSequences, minPatternSequences, minSupportPercent, minTransitionSample);
    }

    @Override
    public ResponseSequenceAnalysisResponse getResponseSequences(Long developerId) {
        log.info("Analysing response sequences for developer id: {}", developerId);

        if (!developerRepository.existsById(developerId)) {
            throw new ResourceNotFoundException("Developer", "id", developerId);
        }

        Set<Long> ownEventIds = securityEventRepository.findByDeveloperId(developerId).stream()
                .map(SecurityEvent::getId)
                .collect(Collectors.toSet());

        // findByDeveloperId loads the event with each log (@EntityGraph)
        List<ActionRecord> actions = behaviourLogRepository.findByDeveloperId(developerId).stream()
                .map(l -> new ActionRecord(
                        l.getId(),
                        l.getSecurityEvent() != null ? l.getSecurityEvent().getId() : null,
                        l.getActionType(),
                        l.getTimestamp()))
                .toList();

        return ResponseSequenceAnalysis.analyse(developerId, actions, ownEventIds, thresholds);
    }
}
