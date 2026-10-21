package com.sentinel.feedback.api;

import com.sentinel.feedback.coach.CoachService;
import com.sentinel.feedback.coach.CoachTypes.Explanation;
import com.sentinel.feedback.coach.CoachTypes.InteractionType;
import com.sentinel.feedback.coach.CoachTypes.Notice;
import com.sentinel.feedback.coach.CoachTypes.OutcomeResult;
import com.sentinel.feedback.coach.CoachTypes.OutcomeType;
import com.sentinel.feedback.coach.CoachTypes.VoteType;
import com.sentinel.feedback.decision.DeveloperHistory;
import com.sentinel.feedback.decision.FeedbackDecision;
import com.sentinel.feedback.decision.FeedbackEvent;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/feedback")
public class FeedbackController {

    private final CoachService coach;

    public FeedbackController(CoachService coach) {
        this.coach = coach;
    }

    /** Rule-based decision with a fatigue-aware delivery channel and a static template. */
    @PostMapping("/decide")
    public FeedbackDecision decide(@Valid @RequestBody DecideRequest request) {
        return coach.decide(request.event(), request.history());
    }

    /** Everything the "Why this level?" panel shows, re-read from the stored decision. */
    @GetMapping("/{id}/explain")
    public Explanation explain(@PathVariable String id) {
        return coach.explain(id);
    }

    /** The IDE reports SHOWN / EXPANDED / DISMISSED; quick dismissals are detected here. */
    @PostMapping("/{id}/interaction")
    public Notice interaction(@PathVariable String id, @Valid @RequestBody InteractionRequest request) {
        return coach.recordInteraction(id, request.type());
    }

    /** FIXED / IGNORED / SNOOZED. Fixes and ignores also update the developer's mastery. */
    @PostMapping("/{id}/outcome")
    public OutcomeResult outcome(@PathVariable String id, @Valid @RequestBody OutcomeRequest request) {
        return coach.recordOutcome(id, request.outcome());
    }

    /** HELPFUL / NOT_HELPFUL / TOO_MUCH from the Why panel. */
    @PostMapping("/{id}/vote")
    public CoachService.VoteResult vote(@PathVariable String id, @Valid @RequestBody VoteRequest request) {
        return coach.recordVote(id, request.vote());
    }

    public record DecideRequest(
            @Valid @NotNull FeedbackEvent event,
            @Valid @NotNull DeveloperHistory history
    ) {
    }

    public record InteractionRequest(@NotNull InteractionType type) {
    }

    public record OutcomeRequest(@NotNull OutcomeType outcome) {
    }

    public record VoteRequest(@NotNull VoteType vote) {
    }
}
