package com.sentinel.feedback.skill;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/** Non-persistent store for simulations and unit tests. */
public class InMemorySkillStore implements SkillStore {

    private final Map<String, Map<String, SkillState>> states = new ConcurrentHashMap<>();
    private final List<SkillEventEntry> events = new CopyOnWriteArrayList<>();

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
    public void save(SkillState state, SkillEventEntry event) {
        states.computeIfAbsent(state.devHash(), key -> new ConcurrentHashMap<>())
                .put(state.cweId(), state);
        events.add(event);
    }

    public List<SkillEventEntry> events() {
        return List.copyOf(events);
    }
}
