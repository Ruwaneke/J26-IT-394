// Smoke test: the committed sample passes the JSON Schema and loads through the
// same parser, types and selectors that the dashboard tabs use.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import Ajv2020 from "ajv/dist/2020";
import { parseAnalytics } from "../src/data/parse";
import {
  classifierSignificance, developerIds, developerTrend, forecastComparison, forecastSeries, heatmap,
  recommendationRows, riskRows, teamTrend,
} from "../src/data/selectors";
import { forecastVerdict, intervalVerdict } from "../src/data/format";
import type { Analytics } from "../src/types/analytics";

const read = (rel: string) => JSON.parse(readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8"));
const schema = read("../../ml/analytics.schema.json");
const raw = read("../public/sample-analytics.json");

describe("sample-analytics.json", () => {
  it("is valid against ml/analytics.schema.json", () => {
    const validate = new Ajv2020({ allErrors: true, strict: false }).compile(schema);
    const ok = validate(raw);
    expect(validate.errors ?? []).toEqual([]);
    expect(ok).toBe(true);
  });

  const data: Analytics = parseAnalytics(raw);

  it("is labelled as simulated", () => {
    expect(data.meta.dataSource).toBe("simulated");
    expect(data.meta.disclaimer.length).toBeGreaterThan(0);
  });

  it("feeds every tab", () => {
    expect(teamTrend(data)).toHaveLength(data.meta.nWeeks);
    const ids = developerIds(data);
    expect(ids.length).toBeGreaterThan(0);
    const trend = developerTrend(data, ids[0]);
    expect(trend?.rows).toHaveLength(data.meta.nWeeks);

    const series = forecastSeries(data, ids[0], "vulnCount", 1)!;
    expect(series.at(-1)?.week).toBe(data.meta.nWeeks + data.forecast.horizon);
    expect(series.some((r) => r.predicted !== null)).toBe(true);
    expect(series.filter((r) => r.band !== null)).toHaveLength(data.forecast.horizon);
    expect(forecastSeries(data, ids[0], "fixRate", 2)!.every((r) => r.predicted === null || (r.predicted >= 0 && r.predicted <= 1))).toBe(true);

    const table = forecastComparison(data);
    expect(table.map((r) => r.model)).toEqual([`${data.forecast.deployed}_ensemble`, "naive", "mean4", "linear"]);

    const risk = riskRows(data, "ALL", "HIGH", true);
    expect(risk).toHaveLength(data.risk.developers.length);
    expect(risk[0].probabilities.HIGH).toBeGreaterThanOrEqual(risk.at(-1)!.probabilities.HIGH);
    expect(riskRows(data, "HIGH", "developerId", false).every((d) => d.band === "HIGH")).toBe(true);
    expect(data.risk.developers.every((d) => d.drivers.every((x) => typeof x.text === "string"))).toBe(true);

    const cells = heatmap(data.correlations.developer, "pearson");
    expect(cells).toHaveLength(data.correlations.developer.variables.length);
    expect(cells.every((row, i) => row[i].diagonal)).toBe(true);

    expect(recommendationRows(data, 1).every((d) => d.priority === 1)).toBe(true);
    expect(classifierSignificance(data).map((s) => s.baseline)).toContain("persistence");
    expect(data.keyFindings.some((k) => k.topic === "summary")).toBe(true);
  });
});

describe("parseAnalytics", () => {
  it("rejects files that are not analytics.json", () => {
    expect(() => parseAnalytics([])).toThrow(/not a JSON object/);
    expect(() => parseAnalytics({ meta: {} })).toThrow(/missing/);
    expect(() => parseAnalytics({ ...raw, meta: { ...raw.meta, dataSource: "real" } })).toThrow(/dataSource/);
  });
});

describe("verdicts match ml/src/export.py", () => {
  it("uses the same rules", () => {
    expect(forecastVerdict(0.01, -0.3)).toBe("beats");
    expect(forecastVerdict(0.2, -0.3)).toBe("ties");
    expect(forecastVerdict(0.01, 0.3)).toBe("worse");
    expect(intervalVerdict(0.01, 0.2)).toBe("beats");
    expect(intervalVerdict(-0.05, 0.07)).toBe("ties");
    expect(intervalVerdict(-0.2, -0.01)).toBe("worse");
  });
});
