package com.sentinel.feedback.persistence;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;

public interface NoticeLogRepository extends JpaRepository<NoticeLogEntity, String> {

    long countByQuickDismissTrueAndDecisionIdIn(Collection<String> decisionIds);
}
