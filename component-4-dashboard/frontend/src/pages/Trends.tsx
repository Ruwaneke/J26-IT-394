import { useState } from "react";
import type { Analytics } from "../types/analytics";
import type { ChartColors } from "../theme/useChartColors";
import { Empty, Picker, Section } from "../components/common";
import { DeveloperTrendChart } from "../charts/charts";
import { num } from "../data/format";
import { developerIds, developerTrend } from "../data/selectors";

export function Trends({ data, colors }: { data: Analytics; colors: ChartColors }) {
  const ids = developerIds(data);
  const [dev, setDev] = useState(ids[0] ?? "");
  const trend = developerTrend(data, dev);
  if (!ids.length) return <Empty>No developer trends in this file.</Empty>;
  return (
    <Section title="Vulnerability introduction rate per developer" note="Findings per coding session, per week. Gaps are inactive weeks. The dashed line is the team rate.">
      <div className="controls">
        <Picker label="Developer" value={dev} options={ids} onChange={setDev} />
        {trend && (
          <span className={`badge trend-${trend.developer.direction}`} aria-live="polite">
            {trend.developer.direction} (slope {num(trend.developer.introRateSlope, 3)} per week)
          </span>
        )}
      </div>
      {trend ? (
        <>
          <DeveloperTrendChart data={trend.rows} colors={colors} />
          <p className="muted small">
            Active weeks: {trend.developer.activeWeeks} of {trend.rows.length}. Fix-rate slope {num(trend.developer.fixRateSlope, 3)} per week.
            The label is "improving" below −0.02 per week, "worsening" above +0.02, otherwise "stable".
          </p>
        </>
      ) : <Empty>No data for {dev}.</Empty>}
    </Section>
  );
}
