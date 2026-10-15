import type { Analytics } from "../types/analytics";

const SECTIONS = [
  "meta", "overview", "trends", "forecast", "forecastEvaluation", "risk",
  "riskEvaluation", "correlations", "recommendations", "keyFindings",
] as const;

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Light runtime check of the contract before the UI uses it. Full validation
 * against analytics.schema.json happens in the pipeline and in the tests; here
 * we only make sure the file is the right kind of document, so a wrong file
 * gives a clear message instead of a blank tab.
 */
export function parseAnalytics(raw: unknown): Analytics {
  if (!isObject(raw)) throw new Error("The data file is not a JSON object.");
  const missing = SECTIONS.filter((k) => !(k in raw));
  if (missing.length) throw new Error(`The data file is missing: ${missing.join(", ")}. Is it analytics.json from the Component 4 pipeline?`);
  const meta = raw.meta;
  if (!isObject(meta) || (meta.dataSource !== "simulated" && meta.dataSource !== "component2")) {
    throw new Error("meta.dataSource must be \"simulated\" or \"component2\".");
  }
  for (const key of ["trends", "forecast", "risk", "recommendations"] as const) {
    const section = raw[key];
    if (!isObject(section) || !Array.isArray(section.developers)) {
      throw new Error(`${key}.developers must be a list.`);
    }
  }
  if (!Array.isArray(raw.keyFindings)) throw new Error("keyFindings must be a list.");
  return raw as unknown as Analytics;
}
