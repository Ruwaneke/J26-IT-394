package com.sentinel.feedback.persistence;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FeedbackOutcomeRepository extends JpaRepository<FeedbackOutcomeEntity, Long> {

    boolean existsByDecisionId(String decisionId);

    List<FeedbackOutcomeEntity> findByDevHashAndCweIdOrderByCreatedAtDescIdDesc(
            String devHash, String cweId, Pageable page);
}
