package com.sentinel.feedback.api;

import com.sentinel.feedback.decision.DecisionService;
import com.sentinel.feedback.decision.DeveloperHistory;
import com.sentinel.feedback.decision.FeedbackDecision;
import com.sentinel.feedback.decision.FeedbackEvent;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/feedback")
public class FeedbackController {

    private final DecisionService decisionService;

    public FeedbackController(DecisionService decisionService) {
        this.decisionService = decisionService;
    }

    /** Fast, rule-based decision plus a static template. */
    @PostMapping("/decide")
    public FeedbackDecision decide(@Valid @RequestBody DecideRequest request) {
        return decisionService.decide(request.event(), request.history());
    }

    public record DecideRequest(
            @Valid @NotNull FeedbackEvent event,
            @Valid @NotNull DeveloperHistory history
    ) {
    }
}
