// Pure functions that shape analytics.json for each tab. Kept free of React so
// the smoke test can run them against the sample file.
import type { Analytics, Band, CorrelationLevel, RiskDeveloper, Target } from "../types/analytics";
import { forecastVerdict, intervalVerdict, isNum, type Verdict } from "./format";

export const BANDS: Band[] = ["LOW", "MEDIUM", "HIGH"];
const BAND_ORDER: Record<Band, number> = { LOW: 0, MEDIUM: 1, HIGH: 2 };

export function developerIds(a: Analytics): string[] {
  return a.trends.developers.map((d) => d.developerId).sort();
}

export function teamTrend(a: Analytics) {
  return a.trends.team.map((w) => ({
    week: w.week,
    vulnCount: w.vulnCount,
    vulnCountMa4: w.vulnCountMa4,
    fixRate: w.fixRate,
    introRate: w.introRatePerSession,
  }));
}

export function developerTrend(a: Analytics, developerId: string) {
  const dev = a.trends.developers.find((d) => d.developerId === developerId);
  if (!dev) return null;
  const team = new Map(a.trends.team.map((w) => [w.week, w.introRatePerSession]));
  return {
    developer: dev,
    rows: dev.weeks.map((w) => ({
      week: w.week,
      introRate: w.active ? w.introRatePerSession : null,
      teamIntroRate: team.get(w.week) ?? null,
      vulnCount: w.vulnCount,
      active: w.active,
    })),
  };
}

export type ForecastRow = {
  week: number;
  actual: number | null;
  predicted: number | null;
  mean4: number | null;
  futureMean: number | null;
  band: [number, number] | null;
};

/** History (weeks 1-16), test predictions for one horizon, and the future forecast with its seed band. */
export function forecastSeries(a: Analytics, developerId: string, target: Target, horizon: number): ForecastRow[] | null {
  const dev = a.forecast.developers.find((d) => d.developerId === developerId);
  if (!dev) return null;
  const deployed = a.forecast.deployed;
  const rows = new Map<number, ForecastRow>();
  const row = (week: number) => {
    if (!rows.has(week)) rows.set(week, { week, actual: null, predicted: null, mean4: null, futureMean: null, band: null });
    return rows.get(week)!;
  };
  for (const h of dev.history) {
    row(h.week).actual = target === "vulnCount" ? (h.active ? h.vulnCount : null) : h.fixRate;
  }
  for (const t of dev.test) {
    if (t.target !== target || t.horizon !== horizon) continue;
    const r = row(t.week);
    const p = t[deployed];
    r.predicted = isNum(p) ? p : null;
    r.mean4 = t.mean4;
  }
  const lastWeek = Math.max(...dev.history.map((h) => h.week));
  const last = rows.get(lastWeek);
  if (last && last.actual !== null) last.futureMean = last.actual; // join the future line to the last actual value
  for (const f of dev.future) {
    const s = f[target];
    const r = row(f.week);
    r.futureMean = s.mean;
    r.band = isNum(s.low) && isNum(s.high) ? [s.low, s.high] : null;
  }
  return [...rows.values()].sort((x, y) => x.week - y.week);
}

export type ForecastTableRow = {
  model: string;
  maeVuln: number | null;
  maeFix: number | null;
  pVuln: number | null;
  pFix: number | null;
  verdictVuln: Verdict | null;
  verdictFix: Verdict | null;
};

/** Deployed seed ensemble vs the three baselines (test weeks, all horizons). */
export function forecastComparison(a: Analytics): ForecastTableRow[] {
  const ev = a.forecastEvaluation;
  const ensemble = `${ev.deployed}_ensemble`;
  const mae = (model: string, target: Target) =>
    ev.metrics.find((m) => m.model === model && m.target === target && m.horizon === "all")?.mae.mean ?? null;
  const wil = (baseline: string, target: Target) =>
    ev.wilcoxon.find((w) => w.model === ensemble && w.baseline === baseline && w.target === target);
  const rows: ForecastTableRow[] = [{
    model: ensemble, maeVuln: mae(ensemble, "vulnCount"), maeFix: mae(ensemble, "fixRate"),
    pVuln: null, pFix: null, verdictVuln: null, verdictFix: null,
  }];
  for (const b of ["naive", "mean4", "linear"]) {
    const wv = wil(b, "vulnCount");
    const wf = wil(b, "fixRate");
    rows.push({
      model: b, maeVuln: mae(b, "vulnCount"), maeFix: mae(b, "fixRate"),
      pVuln: wv?.pValue ?? null, pFix: wf?.pValue ?? null,
      verdictVuln: wv ? forecastVerdict(wv.pValue, wv.medianDiff) : null,
      verdictFix: wf ? forecastVerdict(wf.pValue, wf.medianDiff) : null,
    });
  }
  return rows;
}

export type RiskSortKey = "developerId" | "band" | "LOW" | "MEDIUM" | "HIGH";

export function riskRows(a: Analytics, filter: Band | "ALL", sortKey: RiskSortKey, descending: boolean): RiskDeveloper[] {
  const rows = a.risk.developers.filter((d) => filter === "ALL" || d.band === filter);
  const value = (d: RiskDeveloper): string | number =>
    sortKey === "developerId" ? d.developerId
      : sortKey === "band" ? BAND_ORDER[d.band] * 10 + d.probabilities[d.band]
        : d.probabilities[sortKey];
  return [...rows].sort((x, y) => {
    const vx = value(x);
    const vy = value(y);
    const c = typeof vx === "string" ? vx.localeCompare(vy as string) : (vx as number) - (vy as number);
    return descending ? -c : c;
  });
}

export type HeatCell = {
  row: string; col: string; r: number | null; pAdj: number | null; significant: boolean; diagonal: boolean;
};

export function heatmap(level: CorrelationLevel, method: "pearson" | "spearman"): HeatCell[][] {
  const m = level.matrices[method];
  return level.variables.map((row, i) =>
    level.variables.map((col, j) => ({
      row, col, r: m.r[i][j], pAdj: m.pAdj[i][j], significant: m.significant[i][j], diagonal: i === j,
    })));
}

export function classifierSignificance(a: Analytics) {
  return a.riskEvaluation.significance.map((s) => ({
    ...s,
    verdict: intervalVerdict(s.bootstrapMacroF1Diff.ciLow, s.bootstrapMacroF1Diff.ciHigh),
  }));
}

export function recommendationRows(a: Analytics, priority: 0 | 1 | 2 | 3) {
  const bands = new Map(a.risk.developers.map((d) => [d.developerId, d.band]));
  return a.recommendations.developers
    .filter((d) => priority === 0 || d.priority === priority)
    .map((d) => ({ ...d, band: bands.get(d.developerId) ?? null }))
    .sort((x, y) => x.priority - y.priority || x.developerId.localeCompare(y.developerId));
}
