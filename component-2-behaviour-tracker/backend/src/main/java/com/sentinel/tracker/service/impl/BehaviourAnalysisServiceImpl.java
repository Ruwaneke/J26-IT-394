package com.sentinel.tracker.service.impl;

import com.sentinel.tracker.dto.DeveloperBehaviourSummaryResponse;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.Severity;
import com.sentinel.tracker.exception.ResourceNotFoundException;
import com.sentinel.tracker.repository.BehaviourLogRepository;
import com.sentinel.tracker.repository.DeveloperRepository;
import com.sentinel.tracker.repository.SecurityEventRepository;
import com.sentinel.tracker.service.BehaviourAnalysisService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Implementation of the behaviour analysis service.
 * Calculates metrics dynamically from history and assigns explainable classifications.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class BehaviourAnalysisServiceImpl implements BehaviourAnalysisService {

    private final DeveloperRepository developerRepository;
    private final SecurityEventRepository securityEventRepository;
    private final BehaviourLogRepository behaviourLogRepository;

    @Override
    public DeveloperBehaviourSummaryResponse getDeveloperBehaviourSummary(Long developerId) {
        log.info("Calculating behaviour summary for developer id: {}", developerId);

        if (!developerRepository.existsById(developerId)) {
            throw new ResourceNotFoundException("Developer", "id", developerId);
        }

        List<SecurityEvent> allEvents = securityEventRepository.findByDeveloperId(developerId);
        long totalSecurityEvents = allEvents.size();

        List<BehaviourLog> allLogs = behaviourLogRepository.findByDeveloperId(developerId);

        long openedCount = countActions(allLogs, BehaviourAction.OPEN);
        long fixedCount = countActions(allLogs, BehaviourAction.FIX);
        long ignoredCount = countActions(allLogs, BehaviourAction.IGNORE);
        long dismissedCount = countActions(allLogs, BehaviourAction.DISMISS);
        long reopenedCount = countActions(allLogs, BehaviourAction.REOPEN);

        // Rates are calculated based on the total number of security events assigned to the developer
        double fixRate = calculateRate(fixedCount, totalSecurityEvents);
        double ignoreRate = calculateRate(ignoredCount + dismissedCount, totalSecurityEvents);
        double reopenRate = calculateRate(reopenedCount, totalSecurityEvents);

        // High severity fix rate
        long highSeverityEvents = allEvents.stream()
                .filter(e -> e.getSeverity() == Severity.HIGH || e.getSeverity() == Severity.CRITICAL)
                .count();
        long highSeverityFixedCount = allLogs.stream()
                .filter(l -> l.getActionType() == BehaviourAction.FIX 
                        && l.getSecurityEvent() != null 
                        && (l.getSecurityEvent().getSeverity() == Severity.HIGH || l.getSecurityEvent().getSeverity() == Severity.CRITICAL))
                .count();
        
        double highSeverityFixRate = highSeverityEvents == 0 ? 100.0 : calculateRate(highSeverityFixedCount, highSeverityEvents);

        // Average response time
        double avgResponseTime = allLogs.stream()
                .filter(l -> l.getTimeSinceDetectionSeconds() != null)
                .mapToLong(BehaviourLog::getTimeSinceDetectionSeconds)
                .average()
                .orElse(0.0);

        // Repeated vulnerability count (vulnerability types that appear more than once)
        Map<String, Long> vulnerabilityCounts = allEvents.stream()
                .collect(Collectors.groupingBy(SecurityEvent::getVulnerabilityType, Collectors.counting()));
        
        long repeatedVulnerabilityCount = vulnerabilityCounts.values().stream()
                .filter(count -> count > 1)
                .count();

        // Explainable classification rules
        String classification = determineClassification(
                fixRate, highSeverityFixRate, ignoreRate, reopenRate, 
                repeatedVulnerabilityCount, totalSecurityEvents, allLogs.size());

        return DeveloperBehaviourSummaryResponse.builder()
                .developerId(developerId)
                .totalSecurityEvents(totalSecurityEvents)
                .openedCount(openedCount)
                .fixedCount(fixedCount)
                .ignoredCount(ignoredCount)
                .dismissedCount(dismissedCount)
                .reopenedCount(reopenedCount)
                .fixRate(fixRate)
                .ignoreRate(ignoreRate)
                .reopenRate(reopenRate)
                .highSeverityFixRate(highSeverityFixRate)
                .averageResponseTimeSeconds(Math.round(avgResponseTime * 10.0) / 10.0)
                .repeatedVulnerabilityCount(repeatedVulnerabilityCount)
                .behaviourClassification(classification)
                .build();
    }

    private long countActions(List<BehaviourLog> logs, BehaviourAction action) {
        return logs.stream().filter(l -> l.getActionType() == action).count();
    }

    private double calculateRate(long count, long total) {
        if (total == 0) return 0.0;
        return Math.round((double) count / total * 100.0 * 10.0) / 10.0;
    }

    /**
     * Rule-based intelligence layer for behaviour classification.
     */
    private String determineClassification(double fixRate, double highSeverityFixRate, double ignoreRate, 
                                           double reopenRate, long repeatedVulnerabilityCount, 
                                           long totalEvents, long totalLogs) {
        
        if (totalEvents < 3 || totalLogs < 3) {
            return "INSUFFICIENT_DATA";
        }

        if (fixRate >= 80.0 && highSeverityFixRate >= 80.0 && ignoreRate < 20.0) {
            return "SECURITY_RESPONSIVE";
        }

        if (ignoreRate >= 40.0 || highSeverityFixRate < 50.0) {
            return "SECURITY_AT_RISK";
        }

        if (reopenRate >= 30.0 || repeatedVulnerabilityCount >= 3) {
            return "RECURRING_SECURITY_BEHAVIOUR";
        }

        return "SECURITY_NEUTRAL";
    }
}
