package com.sentinel.feedback.api;

import com.sentinel.feedback.model.VulnerabilityType;
import com.sentinel.feedback.skill.SkillEventType;
import com.sentinel.feedback.skill.SkillModelService;
import com.sentinel.feedback.skill.SkillState;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/skills")
public class SkillController {

    private final SkillModelService skillModel;

    public SkillController(SkillModelService skillModel) {
        this.skillModel = skillModel;
    }

    /** Current (time-decayed) mastery per CWE for one developer. */
    @GetMapping("/{devHash}")
    public List<SkillState> skills(@PathVariable String devHash) {
        return skillModel.currentSkills(devHash);
    }

    /** Records a FIX / IGNORE / REPEAT / REOPEN outcome pushed by Component 2. */
    @PostMapping("/{devHash}/events")
    public SkillState recordEvent(@PathVariable String devHash,
                                  @Valid @RequestBody SkillEventRequest request) {
        String cweId = VulnerabilityType.fromCwe(request.cwe()).cweId();
        return skillModel.record(devHash, cweId, request.eventType());
    }

    public record SkillEventRequest(@NotBlank String cwe, @NotNull SkillEventType eventType) {
    }
}
