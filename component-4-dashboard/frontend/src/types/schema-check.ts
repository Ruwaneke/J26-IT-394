// Compile-time check: every value our Analytics type allows must also fit the type
// generated from ml/analytics.schema.json. If the schema and the app types drift
// apart, `npm run typecheck` (and therefore `npm run build`) fails here.
import type { Analytics } from "./analytics";
import type { Component4AnalyticsContract } from "./schema.generated";

type AssertAssignable<T extends U, U> = T;
export type AnalyticsMatchesSchema = AssertAssignable<Analytics, Component4AnalyticsContract>;
