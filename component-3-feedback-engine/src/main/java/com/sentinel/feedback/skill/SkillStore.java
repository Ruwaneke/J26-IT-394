package com.sentinel.feedback.skill;

import java.util.List;
import java.util.Optional;

/** Persistence boundary for skill states; in-memory now, JPA later. */
public interface SkillStore {

    Optional<SkillState> find(String devHash, String cweId);

    List<SkillState> findAll(String devHash);

    void save(SkillState state);
}
