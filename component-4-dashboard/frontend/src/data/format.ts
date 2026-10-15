import type { Nullable } from "../types/analytics";

export const MODEL_LABELS: Record<string, string> = {
  naive: "Naive last value",
  mean4: "4-week mean",
  linear: "Linear trend",
  xgboost: "XGBoost",
  logreg: "Logistic regression",
  persistence: "Persistence (last 4 weeks)",
  fix_rate_rule: "Fix-rate rule",
  majority: "Majority class",
};

export function modelLabel(name: string): string {
  if (MODEL_LABELS[name]) return MODEL_LABELS[name];
  const ensemble = name.endsWith("_ensemble");
  const base = name.replace(/_ensemble$/, "");
  const [cell, mode] = base.split("_");
  const label = `${(cell ?? base).toUpperCase()} ${mode ?? ""}`.trim();
  return ensemble ? `${label} (seed ensemble)` : label;
}

export const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

export function pct(v: Nullable<number> | undefined, digits = 0): string {
  return isNum(v) ? `${(v * 100).toFixed(digits)}%` : "–";
}

export function num(v: Nullable<number> | undefined, digits = 2): string {
  return isNum(v) ? v.toFixed(digits) : "–";
}

export function minutes(seconds: Nullable<number> | undefined): string {
  return isNum(seconds) ? `${(seconds / 60).toFixed(1)} min` : "–";
}

export function pValue(p: Nullable<number> | undefined): string {
  if (!isNum(p)) return "–";
  if (p < 0.001) return "< 0.001";
  return p.toFixed(3);
}

export function meanStd(m: Nullable<number> | undefined, s: Nullable<number> | undefined, digits = 3): string {
  if (!isNum(m)) return "–";
  return isNum(s) && s > 0 ? `${m.toFixed(digits)} ± ${s.toFixed(digits)}` : m.toFixed(digits);
}

export type Verdict = "beats" | "ties" | "worse";

/** Same rule as ml/src/export.py: Wilcoxon p < 0.05 and the sign of the median error difference. */
export function forecastVerdict(pValueRaw: number, medianDiff: number, alpha = 0.05): Verdict {
  if (pValueRaw < alpha) return medianDiff < 0 ? "beats" : "worse";
  return "ties";
}

/** Same rule as ml/src/export.py: the bootstrap 95% CI of the difference excludes 0. */
export function intervalVerdict(ciLow: number, ciHigh: number): Verdict {
  if (ciLow > 0) return "beats";
  if (ciHigh < 0) return "worse";
  return "ties";
}
