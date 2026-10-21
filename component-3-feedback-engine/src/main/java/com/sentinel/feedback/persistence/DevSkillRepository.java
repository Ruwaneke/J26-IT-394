package com.sentinel.feedback.persistence;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface DevSkillRepository extends JpaRepository<DevSkillEntity, DevSkillEntity.Key> {

    List<DevSkillEntity> findByDevHashOrderByCweId(String devHash);
}
