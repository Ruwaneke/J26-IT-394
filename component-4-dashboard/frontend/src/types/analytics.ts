// Types for analytics.json, the single contract file written by ml/src/export.py.
// They are checked against ml/analytics.schema.json at compile time (schema-check.ts)
// and the sample is validated against the schema at test time (test/sample.test.ts).

export type Nullable<T> = T | null;
export type Band = "LOW" | "MEDIUM" | "HIGH";
export type Target = "vulnCount" | "fixRate";
export type Direction = "improving" | "stable" | "worsening";
export type BandTriple = Record<Band, number>;
export type MeanStd = { mean: Nullable<number>; std: Nullable<number> };

export type Meta = {
  schemaVersion: string;
  generatedAt: string;
  dataSource: "simulated" | "component2";
  disclaimer: string;
  seed: number;
  nDevelopers: number;
  nWeeks: number;
  studyStart: string;
  quick: boolean;
  sample?: { nDevelopersIncluded: number; note: string };
};

export type Overview = {
  nWeeks: number;
  totalEvents: number;
  totalSessions: number;
  activeDevelopers: number;
  fixRate: number;
  ignoreRate: number;
  falsePositiveRate: number;
  avgResponseTimeSec: number;
  introRatePerSession: number;
  riskBandCounts: BandTriple;
  priorityCounts: Record<"1" | "2" | "3", number>;
  trendDirections: Partial<Record<Direction, number>>;
};

export type TeamWeek = {
  week: number;
  vulnCount: number;
  activeDevelopers: number;
  sessions: number;
  fixRate: Nullable<number>;
  ignoreRate: Nullable<number>;
  falsePositiveRate: Nullable<number>;
  avgResponseTime: Nullable<number>;
  severityWeightedLoad: number;
  repeatCount: number;
  introRatePerSession: Nullable<number>;
  vulnCountMa4: Nullable<number>;
  fixRateMa4: Nullable<number>;
  vulnCountWow: Nullable<number>;
  byType: Record<string, number>;
};

export type DeveloperWeek = {
  week: number;
  active: boolean;
  vulnCount: number;
  fixRate: Nullable<number>;
  introRatePerSession: Nullable<number>;
  vulnCountMa4: Nullable<number>;
  vulnCountSlope4: Nullable<number>;
};

export type DeveloperTrend = {
  developerId: string;
  introRateSlope: Nullable<number>;
  fixRateSlope: Nullable<number>;
  direction: Direction;
  activeWeeks: number;
  weeks: DeveloperWeek[];
};

export type Spread = { mean: Nullable<number>; low: Nullable<number>; high: Nullable<number> };

export type ForecastTestRecord = {
  originWeek: number;
  week: number;
  horizon: number;
  target: Target;
  actual: Nullable<number>;
  band: { low: Nullable<number>; high: Nullable<number> };
  naive: Nullable<number>;
  mean4: Nullable<number>;
  linear: Nullable<number>;
  // one column per trained variant, e.g. gru_raw, lstm_residual (seed-ensemble predictions)
  [variant: string]: Nullable<number> | string | { low: Nullable<number>; high: Nullable<number> };
};

export type ForecastDeveloper = {
  developerId: string;
  history: { week: number; vulnCount: number; fixRate: Nullable<number>; active: boolean }[];
  test: ForecastTestRecord[];
  future: { week: number; horizon: number; vulnCount: Spread; fixRate: Spread }[];
};

export type Forecast = {
  deployed: string;
  window: number;
  horizon: number;
  bandNote: "seed spread, not a calibrated confidence interval";
  developers: ForecastDeveloper[];
};

export type ForecastMetric = {
  model: string;
  target: Target;
  horizon: "all" | number;
  mae: MeanStd;
  rmse: MeanStd;
  smape: MeanStd;
};

export type WilcoxonRow = {
  model: string;
  baseline: "naive" | "mean4" | "linear";
  target: Target;
  nDevelopers: number;
  medianDiff: number;
  modelBetterShare: number;
  pValue: number;
};

export type ForecastVariant = {
  cell: string;
  targetMode: "raw" | "residual";
  hidden: number;
  window: number;
  dropout: number;
  valScore: number;
  bestEpochs: number[];
};

export type ForecastEvaluation = {
  split: Record<"train" | "validation" | "test", { origins: number[]; targetWeeks: number[] }>;
  seeds: number[];
  nTestWindows: number;
  nTestTargets: Record<Target, number>;
  selectionScore: string;
  residualNote: string;
  selected: Record<string, ForecastVariant>;
  deployed: string;
  deploymentSteps: number;
  metrics: ForecastMetric[];
  wilcoxon: WilcoxonRow[];
  archetypeMaeNote: "diagnostic, simulated data only";
  archetypeMae: { archetype: string; model: string; target: Target; mae: number; nDevelopers: number }[];
};

export type Driver = {
  metric: string;
  value: number;
  studyMedian: number;
  direction: "worse" | "better" | "same";
  text: string;
};

export type RiskDeveloper = {
  developerId: string;
  band: Band;
  probabilities: BandTriple;
  drivers: Driver[];
  scoreHistory: { week: number; score: Nullable<number>; band: Nullable<Band> }[];
};

export type Risk = {
  framing: string;
  thresholds: { medium: number; high: number };
  scoredAtWeek: number;
  predictsWeeks: number[];
  driversNote: string;
  scoreHistoryNote: string;
  developers: RiskDeveloper[];
};

export type ClassifierModel = "xgboost" | "logreg" | "persistence" | "fix_rate_rule" | "majority";

export type ClassificationMetrics = {
  model: string;
  accuracy: number;
  macroPrecision: number;
  macroRecall: number;
  macroF1: number;
  recall: BandTriple;
  confusionMatrix: number[][];
};

export type RiskEvaluation = {
  headlineMethod: string;
  postHocNote: string;
  scoreWeights: Record<string, number>;
  labelNormaliser: Record<string, number[]>;
  featureSets: Record<string, number>;
  classBalance: Record<string, BandTriple>;
  selected: {
    xgboost: Record<string, number>;
    logreg: { C: number };
    selectionCvMacroF1: number;
    deploymentTrees: number;
  };
  headline: {
    model: ClassifierModel;
    macroF1: { mean: number; std: number; ciLow: number; ciHigh: number };
    accuracy: MeanStd;
    recallHigh: MeanStd;
    confusionMatrixSum: number[][];
  }[];
  significance: {
    baseline: ClassifierModel;
    bootstrapMacroF1Diff: { meanDiff: number; ciLow: number; ciHigh: number; xgbBetterShare: number };
    mcnemarRepeat1: { onlyXgbCorrect: number; onlyBaselineCorrect: number; pValue: number; note: string };
  }[];
  round1: { note: string; originalFeatures: ClassificationMetrics[]; extendedFeatures: ClassificationMetrics[] };
  featureImportance: { feature: string; gain: number; meanAbsShap: number }[];
  featureImportanceNote: string;
};

export type CorrelationResult = {
  r: Nullable<number>;
  p: Nullable<number>;
  ci: [Nullable<number>, Nullable<number>];
  pAdj: Nullable<number>;
  significant: boolean;
};

export type Heatmap = {
  r: Nullable<number>[][];
  pAdj: Nullable<number>[][];
  significant: boolean[][];
};

export type CorrelationLevel = {
  level: "developer" | "developer-week";
  note: string;
  variables: string[];
  alpha: number;
  correction: "benjamini-hochberg";
  nTests: number;
  pairs: { x: string; y: string; n: number; pearson: CorrelationResult; spearman: CorrelationResult }[];
  matrices: { pearson: Heatmap; spearman: Heatmap };
};

export type Recommendation = { ruleId: string; priority: 1 | 2 | 3; text: string };

export type RecommendationDeveloper = {
  developerId: string;
  priority: 1 | 2 | 3;
  recommendations: Recommendation[];
  firedRules: string[];
  inputs: Record<string, string | number | null>;
};

export type KeyFinding = { topic: "data" | "forecast" | "risk" | "summary" | "correlation"; text: string };

export type Analytics = {
  meta: Meta;
  overview: Overview;
  trends: { team: TeamWeek[]; developers: DeveloperTrend[] };
  forecast: Forecast;
  forecastEvaluation: ForecastEvaluation;
  risk: Risk;
  riskEvaluation: RiskEvaluation;
  correlations: {
    variableLabels: Record<string, string>;
    developer: CorrelationLevel;
    week: CorrelationLevel;
  };
  recommendations: {
    framing: string;
    rules: { id: string; priority: number; when: { field: string; op: string; value?: unknown }[] }[];
    developers: RecommendationDeveloper[];
  };
  keyFindings: KeyFinding[];
};
