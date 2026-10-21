package com.sentinel.feedback.coach;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.feedback.coach.CoachTypes.Explanation;
import com.sentinel.feedback.coach.CoachTypes.FatigueAnalytics;
import com.sentinel.feedback.coach.CoachTypes.HourBucket;
import com.sentinel.feedback.coach.CoachTypes.InteractionType;
import com.sentinel.feedback.coach.CoachTypes.MasteryPoint;
import com.sentinel.feedback.coach.CoachTypes.Notice;
import com.sentinel.feedback.coach.CoachTypes.OutcomeResult;
import com.sentinel.feedback.coach.CoachTypes.OutcomeType;
import com.sentinel.feedback.coach.CoachTypes.VoteType;
import com.sentinel.feedback.decision.Channel;
import com.sentinel.feedback.decision.DecisionService;
import com.sentinel.feedback.decision.DeveloperHistory;
import com.sentinel.feedback.decision.FeedbackDecision;
import com.sentinel.feedback.decision.FeedbackEvent;
import com.sentinel.feedback.decision.FeedbackLevel;
import com.sentinel.feedback.decision.LevelMapper;
import com.sentinel.feedback.decision.ScoreBreakdown;
import com.sentinel.feedback.model.VulnerabilityType;
import com.sentinel.feedback.persistence.FeedbackDecisionEntity;
import com.sentinel.feedback.persistence.FeedbackDecisionRepository;
import com.sentinel.feedback.persistence.FeedbackOutcomeEntity;
import com.sentinel.feedback.persistence.FeedbackOutcomeRepository;
import com.sentinel.feedback.persistence.FeedbackVoteEntity;
import com.sentinel.feedback.persistence.FeedbackVoteRepository;
import com.sentinel.feedback.persistence.NoticeLogEntity;
import com.sentinel.feedback.persistence.NoticeLogRepository;
import com.sentinel.feedback.persistence.SkillEventRepository;
import com.sentinel.feedback.policy.PolicyProperties;
import com.sentinel.feedback.recommendation.RecommendationTemplateService;
import com.sentinel.feedback.skill.SkillEventType;
import com.sentinel.feedback.skill.SkillModelService;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * Plan B: turns a rule-based decision into a delivered notice. It applies de-escalation
 * from recent quick fixes, picks a fatigue-aware channel, writes the "Why this level?"
 * narrative, stores the decision, and records what the developer did with it.
 */
@Service
public class CoachService {

    private static final TypeReference<List<String>> STRING_LIST = new TypeReference<>() {
    };

    private final PolicyProperties policy;
    private final DecisionService decisions;
    private final LevelMapper levelMapper;
    private final FatiguePolicy fatiguePolicy;
    private final NarrativeService narratives;
    private final SkillModelService skillModel;
    private final RecommendationTemplateService templates;
    private final FeedbackDecisionRepository decisionRepo;
    private final NoticeLogRepository noticeRepo;
    private final FeedbackOutcomeRepository outcomeRepo;
    private final FeedbackVoteRepository voteRepo;
    private final SkillEventRepository skillEventRepo;
    private final ObjectMapper json;
    private final Clock clock;

    @SuppressWarnings("java:S107")
    public CoachService(PolicyProperties policy, DecisionService decisions, LevelMapper levelMapper,
                        FatiguePolicy fatiguePolicy, NarrativeService narratives, SkillModelService skillModel,
                        RecommendationTemplateService templates, FeedbackDecisionRepository decisionRepo,
                        NoticeLogRepository noticeRepo, FeedbackOutcomeRepository outcomeRepo,
                        FeedbackVoteRepository voteRepo, SkillEventRepository skillEventRepo, ObjectMapper json,
                        Clock clock) {
        this.policy = policy;
        this.decisions = decisions;
        this.levelMapper = levelMapper;
        this.fatiguePolicy = fatiguePolicy;
        this.narratives = narratives;
        this.skillModel = skillModel;
        this.templates = templates;
        this.decisionRepo = decisionRepo;
        this.noticeRepo = noticeRepo;
        this.outcomeRepo = outcomeRepo;
        this.voteRepo = voteRepo;
        this.skillEventRepo = skillEventRepo;
        this.json = json;
        this.clock = clock;
    }

    @Transactional
    public FeedbackDecision decide(FeedbackEvent event, DeveloperHistory history) {
        Instant now = clock.instant();
        VulnerabilityType type = VulnerabilityType.fromCwe(event.cwe());
        String devHash = history.devHash();
        String file = event.file() == null ? "" : event.file().trim();

        FeedbackDecision decision = decisions.decide(event, history, quickFixStreak(devHash, type.cweId()));

        PolicyProperties.Fatigue fatigue = policy.fatigue();
        boolean exempt = fatigue.exemptCwes().contains(type.cweId())
                || fatigue.exemptSeverities().contains(event.severity());
        long interruptions = decisionRepo.countByDevHashAndInterruptiveTrueAndCreatedAtAfter(
                devHash, now.minus(Duration.ofHours(1)));
        Instant lastSameIssue = file.isEmpty() ? null
                : decisionRepo.findFirstByDevHashAndCweIdAndFileRefAndInterruptiveTrueOrderByCreatedAtDesc(
                        devHash, type.cweId(), file)
                .map(FeedbackDecisionEntity::getCreatedAt)
                .orElse(null);
        FatiguePolicy.Delivery delivery = fatiguePolicy.apply(decision.channel(), exempt, interruptions,
                lastSameIssue, now);

        String narrative = narratives.build(decision, type, event.severity(), history, delivery.notes());
        FeedbackDecision delivered = decision.withDelivery(delivery.channel(), delivery.notes(), narrative);

        decisionRepo.save(new FeedbackDecisionEntity(
                delivered.decisionId(), event.eventId(), devHash, type.cweId(), event.severity().name(), file,
                delivered.score(), levelMapper.map(delivered.score()).number(), delivered.level(),
                delivered.channel().name(), delivered.channel().interruptive(), delivered.mastery(),
                write(delivered.breakdown()), write(delivered.reasons()), write(delivered.adjustments()),
                write(delivered.deliveryNotes()), narrative, delivered.policyVersion(), now));
        noticeRepo.save(new NoticeLogEntity(delivered.decisionId()));
        return delivered;
    }

    @Transactional(readOnly = true)
    public Explanation explain(String decisionId) {
        FeedbackDecisionEntity entity = find(decisionId);
        VulnerabilityType type = VulnerabilityType.fromCwe(entity.getCweId());
        FeedbackDecision decision = new FeedbackDecision(
                entity.getId(), entity.getEventId(), entity.getCweId(), entity.getLevel(),
                FeedbackLevel.of(entity.getLevel()).displayName(), entity.getScore(),
                read(entity.getBreakdownJson(), ScoreBreakdown.class), entity.getMastery(),
                readList(entity.getReasonsJson()), readList(entity.getAdjustmentsJson()),
                entity.getPolicyVersion(), templates.getTemplate(type), Channel.valueOf(entity.getChannel()),
                readList(entity.getDeliveryNotesJson()), entity.getNarrative());
        List<MasteryPoint> history = skillEventRepo
                .findByDevHashAndCweIdOrderByCreatedAtAscIdAsc(entity.getDevHash(), entity.getCweId()).stream()
                .map(e -> new MasteryPoint(e.getCreatedAt(), e.getMasteryAfter()))
                .toList();
        Notice notice = noticeRepo.findById(decisionId)
                .map(n -> new Notice(n.getShownAt(), n.isExpanded(), n.getDismissedAt(), n.isQuickDismiss()))
                .orElse(null);
        return new Explanation(decision, entity.getSeverity(), entity.getFileRef(), entity.getBaseLevel(),
                entity.getCreatedAt(), history, notice);
    }

    @Transactional
    public Notice recordInteraction(String decisionId, InteractionType type) {
        find(decisionId);
        Instant now = clock.instant();
        NoticeLogEntity notice = noticeRepo.findById(decisionId).orElseGet(() -> new NoticeLogEntity(decisionId));
        switch (type) {
            case SHOWN -> notice.markShown(now);
            case EXPANDED -> notice.markExpanded();
            case DISMISSED -> notice.markDismissed(now, policy.fatigue().quickDismissSeconds());
        }
        noticeRepo.save(notice);
        return new Notice(notice.getShownAt(), notice.isExpanded(), notice.getDismissedAt(), notice.isQuickDismiss());
    }

    /** Records what the developer did; fixes and ignores also update the skill model. */
    @Transactional
    public OutcomeResult recordOutcome(String decisionId, OutcomeType outcome) {
        FeedbackDecisionEntity decision = find(decisionId);
        if (outcomeRepo.existsByDecisionId(decisionId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Outcome already recorded for " + decisionId);
        }
        Instant now = clock.instant();
        long seconds = Math.max(0, Duration.between(decision.getCreatedAt(), now).getSeconds());
        outcomeRepo.save(new FeedbackOutcomeEntity(decisionId, decision.getDevHash(), decision.getCweId(),
                outcome.name(), seconds, now));
        switch (outcome) {
            case FIXED -> skillModel.record(decision.getDevHash(), decision.getCweId(), SkillEventType.FIX);
            case IGNORED -> skillModel.record(decision.getDevHash(), decision.getCweId(), SkillEventType.IGNORE);
            case SNOOZED -> { }
        }
        boolean quickFix = outcome == OutcomeType.FIXED && seconds <= policy.fatigue().quickFixMinutes() * 60L;
        return new OutcomeResult(decisionId, outcome, seconds, quickFix,
                skillModel.currentMastery(decision.getDevHash(), decision.getCweId()));
    }

    @Transactional
    public VoteResult recordVote(String decisionId, VoteType vote) {
        FeedbackDecisionEntity decision = find(decisionId);
        voteRepo.save(new FeedbackVoteEntity(decisionId, decision.getDevHash(), vote.name(), clock.instant()));
        return new VoteResult(decisionId, vote);
    }

    @Transactional(readOnly = true)
    public FatigueAnalytics fatigue(String devHash) {
        Instant now = clock.instant();
        Instant dayAgo = now.minus(Duration.ofHours(24));
        int budget = policy.fatigue().interruptsPerHour();
        long lastHour = decisionRepo.countByDevHashAndInterruptiveTrueAndCreatedAtAfter(
                devHash, now.minus(Duration.ofHours(1)));
        List<FeedbackDecisionEntity> day = decisionRepo.findByDevHashAndCreatedAtAfterOrderByCreatedAt(devHash, dayAgo);
        long quickDismissals = day.isEmpty() ? 0
                : noticeRepo.countByQuickDismissTrueAndDecisionIdIn(day.stream().map(FeedbackDecisionEntity::getId).toList());

        List<HourBucket> buckets = new ArrayList<>();
        Instant currentHour = now.truncatedTo(ChronoUnit.HOURS);
        for (int i = 23; i >= 0; i--) {
            Instant start = currentHour.minus(Duration.ofHours(i));
            Instant end = start.plus(Duration.ofHours(1));
            List<FeedbackDecisionEntity> inHour = day.stream()
                    .filter(d -> !d.getCreatedAt().isBefore(start) && d.getCreatedAt().isBefore(end))
                    .toList();
            buckets.add(new HourBucket(start, (int) inHour.stream().filter(FeedbackDecisionEntity::isInterruptive).count(),
                    inHour.size()));
        }
        return new FatigueAnalytics(devHash, budget, lastHour, (double) lastHour / budget, day.size(), quickDismissals,
                voteRepo.countByDevHashAndVoteAndCreatedAtAfter(devHash, VoteType.HELPFUL.name(), dayAgo),
                voteRepo.countByDevHashAndVoteAndCreatedAtAfter(devHash, VoteType.NOT_HELPFUL.name(), dayAgo),
                voteRepo.countByDevHashAndVoteAndCreatedAtAfter(devHash, VoteType.TOO_MUCH.name(), dayAgo),
                buckets);
    }

    /** True when the developer's last N outcomes for this CWE were all fixes within the quick-fix window. */
    private boolean quickFixStreak(String devHash, String cweId) {
        PolicyProperties.Fatigue fatigue = policy.fatigue();
        int needed = fatigue.deEscalationQuickFixes();
        List<FeedbackOutcomeEntity> recent = outcomeRepo.findByDevHashAndCweIdOrderByCreatedAtDescIdDesc(
                devHash, cweId, PageRequest.of(0, needed));
        return recent.size() == needed && recent.stream().allMatch(o ->
                OutcomeType.FIXED.name().equals(o.getOutcome())
                        && o.getTimeToOutcomeSec() <= fatigue.quickFixMinutes() * 60L);
    }

    private FeedbackDecisionEntity find(String decisionId) {
        return decisionRepo.findById(decisionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No decision " + decisionId));
    }

    private String write(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not serialise decision data", e);
        }
    }

    private <T> T read(String value, Class<T> type) {
        try {
            return json.readValue(value, type);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Stored decision data is unreadable", e);
        }
    }

    private List<String> readList(String value) {
        try {
            return json.readValue(value, STRING_LIST);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Stored decision data is unreadable", e);
        }
    }

    public record VoteResult(String decisionId, VoteType vote) {
    }
}
