package com.sentinel.feedback.api;

import com.sentinel.feedback.coach.CoachService;
import com.sentinel.feedback.coach.CoachTypes.FatigueAnalytics;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/analytics")
public class AnalyticsController {

    private final CoachService coach;

    public AnalyticsController(CoachService coach) {
        this.coach = coach;
    }

    /** Fatigue index and annoyance signals for one developer, for Component 4. */
    @GetMapping("/fatigue")
    public FatigueAnalytics fatigue(@RequestParam("dev") String devHash) {
        return coach.fatigue(devHash);
    }
}
