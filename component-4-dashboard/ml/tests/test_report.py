import copy
import json
import re

import pytest

from src.config import load_config, resolve
from src.export import forecast_verdict, interval_verdict
from src.report import (BASELINE_WORDS, TABLE_NAMES, TARGET_WORDS, build_blocks, key_findings, model_name,
                        to_html, to_markdown)

CFG = load_config()
SAMPLE = json.loads(resolve(CFG["export"]["sample_output"]).read_text(encoding="utf-8"))
TARGET_BY_WORDS = {v: k for k, v in TARGET_WORDS.items()}
BASELINE_BY_WORDS = {v: k for k, v in BASELINE_WORDS.items()}


def report(a=SAMPLE):
    return to_markdown(build_blocks(a, CFG, "figures"))


def forecast_truth(a):
    return {(w["model"], w["baseline"], w["target"]): forecast_verdict(w) for w in a["forecastEvaluation"]["wilcoxon"]}


def classifier_truth(a):
    return {s["baseline"]: interval_verdict(s["bootstrapMacroF1Diff"]) for s in a["riskEvaluation"]["significance"]}


def overclaims(text, a):
    """Sentences that say a model 'beats' a baseline the JSON does not mark as beaten. Table rows are skipped."""
    f_truth, c_truth = forecast_truth(a), classifier_truth(a)
    labels = {model_name(n): f"{n}_ensemble" for n in a["forecastEvaluation"]["selected"]}
    problems = []
    for line in text.splitlines():
        if line.lstrip().startswith("|"):
            continue
        for sentence in re.split(r"(?<=\.)\s+", line):
            if "beat" not in sentence:
                continue
            claims = []  # (baseline, target or None)
            for seg in re.findall(r"beats (.*?)(?=;|, and |\bties\b|\bbut\b|\.$|$)", sentence):
                targets = [t for w, t in TARGET_BY_WORDS.items() if f"on {w}" in seg] or [None]
                for words, baseline in BASELINE_BY_WORDS.items():
                    if words in seg:
                        claims += [(baseline, t) for t in targets]
            for words, target in re.findall(r"against (.+?) it beats on (findings per week|fix rate)", sentence):
                claims.append((BASELINE_BY_WORDS[words], TARGET_BY_WORDS[target]))
            if "XGBoost" in sentence:
                problems += [sentence for b, _ in claims if c_truth.get(b) != "beats"]
                continue
            for label, model in labels.items():
                if label in sentence:
                    for b, t in claims:
                        targets = [t] if t else ["vulnCount", "fixRate"]
                        if any(f_truth.get((model, b, tt)) != "beats" for tt in targets):
                            problems.append(sentence)
    return problems


def test_disclaimer_in_markdown_and_html():
    blocks = build_blocks(SAMPLE, CFG, "figures")
    for text in (to_markdown(blocks), to_html(blocks, "t")):
        assert "SIMULATED DATA" in text
        assert SAMPLE["meta"]["disclaimer"] in text
        assert "not real developers" in text


def test_every_forecast_verdict_appears():
    lines = report().splitlines()
    for w in SAMPLE["forecastEvaluation"]["wilcoxon"]:
        start = f"| {model_name(w['model'])} | {TABLE_NAMES[w['baseline']]} | {TARGET_WORDS[w['target']]} |"
        assert any(l.startswith(start) and l.endswith(f"| {forecast_verdict(w)} |") for l in lines), start


def test_every_classifier_verdict_appears():
    lines = report().splitlines()
    for s in SAMPLE["riskEvaluation"]["significance"]:
        verdict = interval_verdict(s["bootstrapMacroF1Diff"])
        assert any(l.startswith(f"| {TABLE_NAMES[s['baseline']]} |") and f"| {verdict} |" in l for l in lines)


def test_no_sentence_overclaims():
    assert overclaims(report(), SAMPLE) == []


def test_checker_catches_overclaims():
    deployed = model_name(SAMPLE["forecastEvaluation"]["deployed"])
    assert overclaims(f"The deployed forecaster ({deployed}) beats the 4-week mean on both targets.", SAMPLE)
    assert overclaims("In repeated grouped cross-validation, XGBoost beats persistence on macro F1.", SAMPLE)


def test_key_findings_state_ties_and_post_hoc():
    text = " ".join(key_findings(SAMPLE))
    assert "ties the 4-week mean" in text
    assert "ties persistence" in text
    assert "Recent behaviour is the strongest predictor" in text
    assert "post-hoc" in text


def test_summary_finding_follows_the_numbers():
    changed = copy.deepcopy(SAMPLE)
    for s in changed["riskEvaluation"]["significance"]:
        if s["baseline"] == "persistence":
            s["bootstrapMacroF1Diff"].update(meanDiff=0.1, ciLow=0.05, ciHigh=0.15)
    text = " ".join(key_findings(changed))
    assert "Recent behaviour is the strongest predictor" not in text
    assert "XGBoost beats" in text and "persistence" in text
    assert overclaims(report(changed), changed) == []


@pytest.mark.parametrize("section", ["Purpose and scope", "Data (simulated)", "Methods", "Results",
                                     "Key findings", "Limitations", "Future work"])
def test_sections_present(section):
    assert section in report()
