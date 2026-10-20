package com.sentinel.tracker.enums;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.EnumSet;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * All 25 from → to pairs of {@link SecurityEventStatus#canTransitionTo}, checked against the
 * table in TECHNICAL_OVERVIEW §4.3 (TASKS P1-3 step 2). A change to the lifecycle must change
 * this table too (TECHNICAL_OVERVIEW §14.4).
 */
class SecurityEventStatusTest {

    @ParameterizedTest(name = "{0} -> {1}: {2}")
    @CsvSource({
            "DETECTED, DETECTED, false",
            "DETECTED, OPENED,   true",
            "DETECTED, IGNORED,  true",
            "DETECTED, REOPENED, false",
            "DETECTED, FIXED,    true",

            "OPENED,   DETECTED, false",
            "OPENED,   OPENED,   false",
            "OPENED,   IGNORED,  true",
            "OPENED,   REOPENED, false",
            "OPENED,   FIXED,    true",

            "IGNORED,  DETECTED, false",
            "IGNORED,  OPENED,   true",
            "IGNORED,  IGNORED,  false",
            "IGNORED,  REOPENED, true",
            "IGNORED,  FIXED,    true",

            "REOPENED, DETECTED, false",
            "REOPENED, OPENED,   true",
            "REOPENED, IGNORED,  true",
            "REOPENED, REOPENED, false",
            "REOPENED, FIXED,    true",

            "FIXED,    DETECTED, false",
            "FIXED,    OPENED,   false",
            "FIXED,    IGNORED,  false",
            "FIXED,    REOPENED, true",
            "FIXED,    FIXED,    false"
    })
    void canTransitionTo_shouldMatchTheDocumentedTable(SecurityEventStatus from, SecurityEventStatus to,
                                                       boolean allowed) {
        assertThat(from.canTransitionTo(to)).isEqualTo(allowed);
        assertThat(from.allowedTransitions().contains(to)).isEqualTo(allowed);
    }

    @Test
    void noStatus_shouldTransitionBackToDetectedOrToItself() {
        for (SecurityEventStatus status : SecurityEventStatus.values()) {
            assertThat(status.allowedTransitions()).doesNotContain(SecurityEventStatus.DETECTED, status);
        }
    }

    @Test
    void ignoredToOpened_mustStayValidForC1() {
        // In C1, ignored findings reappear and can be opened again (TECHNICAL_OVERVIEW §4.3)
        assertThat(SecurityEventStatus.IGNORED.canTransitionTo(SecurityEventStatus.OPENED)).isTrue();
    }

    @Test
    void enumValues_shouldBeTheFiveDocumentedStatuses() {
        assertThat(EnumSet.allOf(SecurityEventStatus.class)).extracting(Enum::name)
                .containsExactly("DETECTED", "OPENED", "IGNORED", "REOPENED", "FIXED");
    }
}
