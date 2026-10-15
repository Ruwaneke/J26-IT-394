package com.sentinel.feedback.scoring;

import com.sentinel.feedback.model.BehaviourHistory;
import com.sentinel.feedback.model.Severity;
import org.springframework.stereotype.Service;

@Service
public class FeedbackEscalationService {

    private static final int IGNORE_ESCALATION_THRESHOLD = 2;
    private static final int FIX_REDUCTION_THRESHOLD = 3;

    public SeverityScore apply(SeverityScore score, BehaviourHistory history) {
        if (history.previousIgnores() >= IGNORE_ESCALATION_THRESHOLD) {
            return adjust(score, 1);
        }
        if (history.previousFixes() >= FIX_REDUCTION_THRESHOLD) {
            return adjust(score, -1);
        }
        return score;
    }

    private SeverityScore adjust(SeverityScore score, int direction) {
        Severity[] levels = Severity.values();
        int adjustedIndex = Math.max(0, Math.min(levels.length - 1,
                score.severity().ordinal() + direction));
        return new SeverityScore(score.score(), levels[adjustedIndex]);
    }
}
