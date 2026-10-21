package com.sentinel.feedback.persistence;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface SkillEventRepository extends JpaRepository<SkillEventEntity, Long> {

    List<SkillEventEntity> findByDevHashAndCweIdOrderByCreatedAtAscIdAsc(String devHash, String cweId);
}
