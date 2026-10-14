import json

import pytest
from jsonschema import Draft202012Validator

from src.config import load_config, resolve
from src.export import clean, forecast_verdict, interval_verdict, sample

CFG = load_config()
SCHEMA = json.loads(resolve(CFG["export"]["schema"]).read_text(encoding="utf-8"))
SAMPLE = resolve(CFG["export"]["sample_output"])
FULL = resolve(CFG["export"]["output"])


def errors(doc):
    return [f"{list(e.absolute_path)}: {e.message}" for e in Draft202012Validator(SCHEMA).iter_errors(doc)]


def test_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_committed_sample_matches_schema():
    doc = json.loads(SAMPLE.read_text(encoding="utf-8"))
    assert errors(doc) == []
    assert doc["meta"]["dataSource"] == "simulated"
    assert len(doc["risk"]["developers"]) <= CFG["export"]["sample_developers"]
    assert SAMPLE.stat().st_size <= CFG["export"]["sample_max_kb"] * 1024


@pytest.mark.skipif(not FULL.exists(), reason="run the pipeline to create outputs/analytics.json")
def test_full_analytics_matches_schema():
    assert errors(json.loads(FULL.read_text(encoding="utf-8"))) == []


def test_schema_rejects_shap_reasons_and_bad_bands():
    doc = json.loads(SAMPLE.read_text(encoding="utf-8"))
    doc["risk"]["developers"][0]["topFactors"] = [{"feature": "x", "shap": 0.1}]
    assert errors(doc)
    doc = json.loads(SAMPLE.read_text(encoding="utf-8"))
    doc["risk"]["developers"][0]["band"] = "VERY HIGH"
    assert errors(doc)
    doc = json.loads(SAMPLE.read_text(encoding="utf-8"))
    doc["meta"]["dataSource"] = "real"
    assert errors(doc)


def test_sample_keeps_shape_and_cuts_developers():
    doc = json.loads(SAMPLE.read_text(encoding="utf-8"))
    small = sample(doc, 3)
    assert len(small["forecast"]["developers"]) == 3
    assert {d["developerId"] for d in small["risk"]["developers"]} == {d["developerId"] for d in small["trends"]["developers"]}
    assert errors(small) == []


def test_clean_removes_nan():
    out = clean({"a": float("nan"), "b": [1.0, float("inf")], "c": {"d": 2}})
    assert out == {"a": None, "b": [1.0, None], "c": {"d": 2}}
    json.dumps(out, allow_nan=False)


def test_verdicts():
    assert forecast_verdict({"pValue": 0.01, "medianDiff": -0.2}) == "beats"
    assert forecast_verdict({"pValue": 0.01, "medianDiff": 0.2}) == "worse"
    assert forecast_verdict({"pValue": 0.3, "medianDiff": -0.2}) == "ties"
    assert interval_verdict({"ciLow": 0.01, "ciHigh": 0.1}) == "beats"
    assert interval_verdict({"ciLow": -0.05, "ciHigh": 0.07}) == "ties"
    assert interval_verdict({"ciLow": -0.2, "ciHigh": -0.01}) == "worse"
