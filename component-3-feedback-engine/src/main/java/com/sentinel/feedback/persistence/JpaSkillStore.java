package com.sentinel.feedback.persistence;

import com.sentinel.feedback.skill.SkillEventEntry;
import com.sentinel.feedback.skill.SkillState;
import com.sentinel.feedback.skill.SkillStore;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Component
public class JpaSkillStore implements SkillStore {

    private final DevSkillRepository skills;
    private final SkillEventRepository events;

    public JpaSkillStore(DevSkillRepository skills, SkillEventRepository events) {
        this.skills = skills;
        this.events = events;
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<SkillState> find(String devHash, String cweId) {
        return skills.findById(new DevSkillEntity.Key(devHash, cweId)).map(this::toState);
    }

    @Override
    @Transactional(readOnly = true)
    public List<SkillState> findAll(String devHash) {
        return skills.findByDevHashOrderByCweId(devHash).stream().map(this::toState).toList();
    }

    @Override
    @Transactional
    public void save(SkillState state, SkillEventEntry event) {
        DevSkillEntity entity = skills.findById(new DevSkillEntity.Key(state.devHash(), state.cweId()))
                .orElseGet(() -> new DevSkillEntity(state.devHash(), state.cweId()));
        entity.update(state.mastery(), state.eventsCount(), state.lastEventAt());
        skills.save(entity);
        events.save(new SkillEventEntity(event.devHash(), event.cweId(), event.eventType(),
                event.masteryBefore(), event.masteryAfter(), event.createdAt()));
    }

    private SkillState toState(DevSkillEntity entity) {
        return new SkillState(entity.getDevHash(), entity.getCweId(), entity.getMastery(),
                entity.getEventsCount(), entity.getLastEventAt());
    }
}
