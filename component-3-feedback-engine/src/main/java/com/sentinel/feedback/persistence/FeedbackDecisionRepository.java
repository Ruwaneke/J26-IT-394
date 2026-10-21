package com.sentinel.feedback.persistence;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface FeedbackDecisionRepository extends JpaRepository<FeedbackDecisionEntity, String> {

    long countByDevHashAndInterruptiveTrueAndCreatedAtAfter(String devHash, Instant after);

    Optional<FeedbackDecisionEntity> findFirstByDevHashAndCweIdAndFileRefAndInterruptiveTrueOrderByCreatedAtDesc(
            String devHash, String cweId, String fileRef);

    List<FeedbackDecisionEntity> findByDevHashAndCreatedAtAfterOrderByCreatedAt(String devHash, Instant after);
}
