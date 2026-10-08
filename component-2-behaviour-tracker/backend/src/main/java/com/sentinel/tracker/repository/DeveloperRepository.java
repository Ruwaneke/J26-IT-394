package com.sentinel.tracker.repository;

import com.sentinel.tracker.entity.Developer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Spring Data JPA repository for {@link Developer} entities.
 */
@Repository
public interface DeveloperRepository extends JpaRepository<Developer, Long> {

    /**
     * Find a developer by their unique identifier (e.g. GitHub username, employee ID).
     */
    Optional<Developer> findByDeveloperIdentifier(String developerIdentifier);

    /**
     * Check whether a developer with the given identifier already exists.
     */
    boolean existsByDeveloperIdentifier(String developerIdentifier);

    /**
     * Find a developer by their GitHub numeric user ID.
     * Used by the GitHub auth integration to locate existing accounts.
     */
    Optional<Developer> findByGithubId(String githubId);
}
