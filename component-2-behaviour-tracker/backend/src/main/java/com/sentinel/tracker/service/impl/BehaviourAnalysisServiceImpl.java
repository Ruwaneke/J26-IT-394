package com.sentinel.tracker.service.impl;

import com.sentinel.tracker.dto.DeveloperBehaviourSummaryResponse;
import com.sentinel.tracker.entity.BehaviourLog;
import com.sentinel.tracker.entity.SecurityEvent;
import com.sentinel.tracker.enums.BehaviourAction;
import com.sentinel.tracker.enums.FixVerificationStatus;
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

import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Implementation of the behaviour analysis service.
 * Calculates metrics dynamically from history and assigns explainable classifications.
 *
 * Action counts are the number of distinct security events (owned by the developer)
 * that received the action at least once, so repeated actions on the same event are
 * counted once and every rate stays within 0–100%.
 *
 * A FIX action is a claim: fixedCount and fixRate count claimed fixes, and the classification
 * uses them unchanged. verifiedFixCount and verifiedFixRate count only fixes whose
 * verification is VERIFIED.
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

        // Only actions on the developer's own events count towards the rates
        Set<Long> ownEventIds = allEvents.stream()
                .map(SecurityEvent::getId)
                .collect(Collectors.toSet());

        Set<Long> openedEventIds = eventIdsWithAction(allLogs, ownEventIds, EnumSet.of(BehaviourAction.OPEN));
        Set<Long> fixedEventIds = eventIdsWithAction(allLogs, ownEventIds, EnumSet.of(BehaviourAction.FIX));
        Set<Long> ignoredEventIds = eventIdsWithAction(allLogs, ownEventIds, EnumSet.of(BehaviourAction.IGNORE));
        Set<Long> dismissedEventIds = eventIdsWithAction(allLogs, ownEventIds, EnumSet.of(BehaviourAction.DISMISS));
        Set<Long> reopenedEventIds = eventIdsWithAction(allLogs, ownEventIds, EnumSet.of(BehaviourAction.REOPEN));
        // An event both ignored and dismissed counts once towards the ignore rate
        Set<Long> ignoredOrDismissedEventIds = eventIdsWithAction(allLogs, ownEventIds,
                EnumSet.of(BehaviourAction.IGNORE, BehaviourAction.DISMISS));
        // A FIX is a claim; only fixes a verification source confirmed count as verified
        Set<Long> verifiedFixEventIds = eventIdsWithAction(
                allLogs.stream()
                        .filter(l -> l.getFixVerification() == FixVerificationStatus.VERIFIED)
                        .toList(),
                ownEventIds, EnumSet.of(BehaviourAction.FIX));

        // Rates are calculated based on the total number of security events assigned to the developer
        double fixRate = calculateRate(fixedEventIds.size(), totalSecurityEvents);
        double verifiedFixRate = calculateRate(verifiedFixEventIds.size(), totalSecurityEvents);
        double ignoreRate = calculateRate(ignoredOrDismissedEventIds.size(), totalSecurityEvents);
        double reopenRate = calculateRate(reopenedEventIds.size(), totalSecurityEvents);

        // High severity fix rate – null (not applicable) when the developer has no HIGH/CRITICAL events
        Set<Long> highSeverityEventIds = allEvents.stream()
                .filter(e -> e.getSeverity() == Severity.HIGH || e.getSeverity() == Severity.CRITICAL)
                .map(SecurityEvent::getId)
                .collect(Collectors.toSet());
        long highSeverityFixedCount = fixedEventIds.stream()
                .filter(highSeverityEventIds::contains)
                .count();
        Double highSeverityFixRate = highSeverityEventIds.isEmpty()
                ? null
                : calculateRate(highSeverityFixedCount, highSeverityEventIds.size());

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
                .openedCount((long) openedEventIds.size())
                .fixedCount((long) fixedEventIds.size())
                .ignoredCount((long) ignoredEventIds.size())
                .dismissedCount((long) dismissedEventIds.size())
                .reopenedCount((long) reopenedEventIds.size())
                .fixRate(fixRate)
                .verifiedFixCount((long) verifiedFixEventIds.size())
                .verifiedFixRate(verifiedFixRate)
                .ignoreRate(ignoreRate)
                .reopenRate(reopenRate)
                .highSeverityFixRate(highSeverityFixRate)
                .averageResponseTimeSeconds(Math.round(avgResponseTime * 10.0) / 10.0)
                .repeatedVulnerabilityCount(repeatedVulnerabilityCount)
                .behaviourClassification(classification)
                .build();
    }

    /**
     * Distinct ids of the developer's own security events that received any of the given actions.
     * Logs without a security event, or on events not owned by the developer, are ignored.
     */
    private Set<Long> eventIdsWithAction(List<BehaviourLog> logs, Set<Long> ownEventIds,
                                         Set<BehaviourAction> actions) {
        return logs.stream()
                .filter(l -> actions.contains(l.getActionType()))
                .filter(l -> l.getSecurityEvent() != null)
                .map(l -> l.getSecurityEvent().getId())
                .filter(ownEventIds::contains)
                .collect(Collectors.toSet());
    }

    /**
     * Percentage of {@code count} over {@code total}, rounded to one decimal and capped at 100.
     */
    private double calculateRate(long count, long total) {
        if (total == 0) return 0.0;
        double rate = Math.round((double) count / total * 100.0 * 10.0) / 10.0;
        return Math.min(rate, 100.0);
    }

    /**
     * Rule-based intelligence layer for behaviour classification.
     * A null highSeverityFixRate (no HIGH/CRITICAL events) means the high-severity rule does not apply.
     */
    private String determineClassification(double fixRate, Double highSeverityFixRate, double ignoreRate,
                                           double reopenRate, long repeatedVulnerabilityCount,
                                           long totalEvents, long totalLogs) {

        if (totalEvents < 3 || totalLogs < 3) {
            return "INSUFFICIENT_DATA";
        }

        boolean highSeverityHandled = highSeverityFixRate == null || highSeverityFixRate >= 80.0;
        boolean highSeverityNeglected = highSeverityFixRate != null && highSeverityFixRate < 50.0;

        if (fixRate >= 80.0 && highSeverityHandled && ignoreRate < 20.0) {
            return "SECURITY_RESPONSIVE";
        }

        if (ignoreRate >= 40.0 || highSeverityNeglected) {
            return "SECURITY_AT_RISK";
        }

        if (reopenRate >= 30.0 || repeatedVulnerabilityCount >= 3) {
            return "RECURRING_SECURITY_BEHAVIOUR";
        }

        return "SECURITY_NEUTRAL";
    }
}
