package com.sentinel.feedback.sim;

import com.sentinel.feedback.model.Severity;
import com.sentinel.feedback.skill.SkillEventType;

import java.util.List;

/** One rubric-labelled scenario from scenarios.json (see tools/generate_scenarios.py). */
record Scenario(
        String id,
        String set,
        String situation,
        String description,
        EventInput event,
        HistoryInput history,
        List<SkillEventInput> skillEvents,
        int expectedLevel,
        String rationale
) {
    Scenario {
        skillEvents = skillEvents == null ? List.of() : List.copyOf(skillEvents);
    }

    boolean isHeldOut() {
        return set.equals("heldout");
    }

    record EventInput(String cwe, Severity severity) {
    }

    record HistoryInput(int repeats30d, int ignored30d, int fixed30d, int reopened30d,
                        Integer lastSimilarDaysAgo) {
    }

    record SkillEventInput(SkillEventType type, int daysAgo) {
    }
}
