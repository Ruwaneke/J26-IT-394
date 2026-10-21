package com.sentinel.feedback.skill;

import java.util.List;
import java.util.Optional;

/** Persistence boundary for skill states and their event log. */
public interface SkillStore {

    Optional<SkillState> find(String devHash, String cweId);

    List<SkillState> findAll(String devHash);

    /** Saves the new state and the event that produced it together. */
    void save(SkillState state, SkillEventEntry event);
}
