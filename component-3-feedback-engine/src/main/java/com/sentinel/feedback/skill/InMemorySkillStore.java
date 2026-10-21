package com.sentinel.feedback.skill;

import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemorySkillStore implements SkillStore {

    private final Map<String, Map<String, SkillState>> states = new ConcurrentHashMap<>();

    @Override
    public Optional<SkillState> find(String devHash, String cweId) {
        return Optional.ofNullable(states.getOrDefault(devHash, Map.of()).get(cweId));
    }

    @Override
    public List<SkillState> findAll(String devHash) {
        return states.getOrDefault(devHash, Map.of()).values().stream()
                .sorted(Comparator.comparing(SkillState::cweId))
                .toList();
    }

    @Override
    public void save(SkillState state) {
        states.computeIfAbsent(state.devHash(), key -> new ConcurrentHashMap<>())
                .put(state.cweId(), state);
    }
}
