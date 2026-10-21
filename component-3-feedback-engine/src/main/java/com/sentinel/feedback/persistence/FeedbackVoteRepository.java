package com.sentinel.feedback.persistence;

import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface FeedbackVoteRepository extends JpaRepository<FeedbackVoteEntity, Long> {

    long countByDevHashAndVoteAndCreatedAtAfter(String devHash, String vote, Instant after);
}
