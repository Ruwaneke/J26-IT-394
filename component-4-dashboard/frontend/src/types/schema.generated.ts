/* Generated from ml/analytics.schema.json by scripts/gen-types.mjs. Do not edit by hand. */

export type Nnum = (number | null)
export type Band = ("LOW" | "MEDIUM" | "HIGH")
/**
 * @minItems 3
 * @maxItems 3
 */
export type Matrix3 = number[][]

/**
 * Single file read by the dashboard. dataSource 'simulated' means the content is generated from stated assumptions, not real developer data.
 */
export interface Component4AnalyticsContract {
meta: {
schemaVersion: string
generatedAt: string
dataSource: ("simulated" | "component2")
disclaimer: string
seed: number
nDevelopers: number
nWeeks: number
studyStart: string
quick: boolean
sample?: {
nDevelopersIncluded: number
note: string
}
}
overview: {
totalEvents: number
totalSessions: number
activeDevelopers: number
fixRate: number
ignoreRate: number
falsePositiveRate: number
avgResponseTimeSec: number
introRatePerSession: number
riskBandCounts: BandTriple
priorityCounts: {

}
trendDirections: {

}
}
trends: {
/**
 * @minItems 1
 */
team: {
week: number
vulnCount: number
fixRate: Nnum
introRatePerSession: Nnum
vulnCountMa4: Nnum
vulnCountWow: Nnum
byType: {
[k: string]: number
}
}[]
/**
 * @minItems 1
 */
developers: {
developerId: string
direction: ("improving" | "stable" | "worsening")
weeks: {
week: number
active: boolean
vulnCount: number
fixRate: Nnum
introRatePerSession: Nnum
vulnCountMa4: Nnum
vulnCountSlope4: Nnum
}[]
}[]
}
forecast: {
deployed: string
window: number
horizon: number
bandNote: "seed spread, not a calibrated confidence interval"
/**
 * @minItems 1
 */
developers: {
developerId: string
history: {
week: number
vulnCount: number
fixRate: Nnum
active: boolean
}[]
test: {
originWeek: number
week: number
horizon: number
target: ("vulnCount" | "fixRate")
actual: Nnum
band: {

}
naive: Nnum
mean4: Nnum
linear: Nnum
[k: string]: Nnum | {

} | number | "vulnCount" | "fixRate"
}[]
future: {
week: number
horizon: number
vulnCount: Spread
fixRate: Spread
}[]
}[]
}
forecastEvaluation: {
residualNote: string
/**
 * @minItems 1
 */
metrics: {
model: string
target: ("vulnCount" | "fixRate")
horizon: ("all" | number)
mae: MeanStd
rmse: MeanStd
smape: MeanStd
}[]
/**
 * @minItems 1
 */
wilcoxon: {
model: string
baseline: ("naive" | "mean4" | "linear")
pValue: number
}[]
archetypeMaeNote: "diagnostic, simulated data only"
archetypeMae: unknown[]
}
risk: {
framing: string
thresholds: {

}
/**
 * @minItems 1
 */
developers: {
developerId: string
band: Band
probabilities: BandTriple
/**
 * @maxItems 5
 */
drivers: {
metric: string
value: number
studyMedian: number
direction: ("worse" | "better" | "same")
text: string
}[]
scoreHistory: {
week: number
score: Nnum
band: (Band | null)
}[]
}[]
}
riskEvaluation: {
/**
 * @minItems 5
 */
headline: {
model: ("xgboost" | "logreg" | "persistence" | "fix_rate_rule" | "majority")
macroF1: {

}
accuracy: MeanStd
recallHigh: MeanStd
confusionMatrixSum: Matrix3
}[]
/**
 * @minItems 1
 */
significance: {
bootstrapMacroF1Diff: {

}
mcnemarRepeat1: {

}
}[]
round1: {
note: string
originalFeatures: ClassificationMetrics[]
extendedFeatures: ClassificationMetrics[]
}
featureImportance: {

}[]
featureImportanceNote: string
}
correlations: {
variableLabels: {
[k: string]: string
}
developer: CorrelationLevel
week: CorrelationLevel
}
recommendations: {
framing: string
rules: unknown[]
/**
 * @minItems 1
 */
developers: {
developerId: string
priority: (1 | 2 | 3)
/**
 * @minItems 1
 * @maxItems 3
 */
recommendations: {
ruleId: string
priority: (1 | 2 | 3)
text: string
}[]
/**
 * @minItems 1
 */
firedRules: string[]
inputs: {

}
}[]
}
/**
 * @minItems 1
 */
keyFindings: {
topic: ("data" | "forecast" | "risk" | "summary" | "correlation")
text: string
}[]
}
export interface BandTriple {
LOW: number
MEDIUM: number
HIGH: number
}
export interface Spread {
mean: Nnum
low: Nnum
high: Nnum
}
export interface MeanStd {
mean: Nnum
std: Nnum
}
export interface ClassificationMetrics {
model: string
accuracy: number
macroPrecision: number
macroRecall: number
macroF1: number
recall: BandTriple
confusionMatrix: Matrix3
}
export interface CorrelationLevel {
level: ("developer" | "developer-week")
note: string
variables: string[]
alpha: number
correction: "benjamini-hochberg"
nTests: number
pairs: {
x: string
y: string
n: number
pearson: CorrelationResult
spearman: CorrelationResult
}[]
matrices: {
pearson: Heatmap
spearman: Heatmap
}
}
export interface CorrelationResult {
r: Nnum
p: Nnum
pAdj: Nnum
/**
 * @minItems 2
 * @maxItems 2
 */
ci: Nnum[]
significant: boolean
}
export interface Heatmap {
r: Nnum[][]
pAdj: Nnum[][]
significant: boolean[][]
}
