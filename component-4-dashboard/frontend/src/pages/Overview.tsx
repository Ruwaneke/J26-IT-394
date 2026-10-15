import type { Analytics } from "../types/analytics";
import type { ChartColors } from "../theme/useChartColors";
import { Kpi, Section } from "../components/common";
import { TeamTrendChart } from "../charts/charts";
import { minutes, num, pct } from "../data/format";
import { teamTrend } from "../data/selectors";

export function Overview({ data, colors }: { data: Analytics; colors: ChartColors }) {
  const o = data.overview;
  const summary = data.keyFindings.find((k) => k.topic === "summary");
  return (
    <>
      <div className="kpis">
        <Kpi label="Developers" value={String(data.meta.nDevelopers)} hint={`${o.activeDevelopers} active`} />
        <Kpi label="Vulnerabilities detected" value={o.totalEvents.toLocaleString()} hint={`${o.nWeeks} weeks`} />
        <Kpi label="Fix rate" value={pct(o.fixRate)} />
        <Kpi label="Ignore rate" value={pct(o.ignoreRate)} />
        <Kpi label="Average response time" value={minutes(o.avgResponseTimeSec)} />
        <Kpi label="Findings per session" value={num(o.introRatePerSession)} />
      </div>
      {summary && <p className="finding-summary">{summary.text}</p>}
      <Section title="Team weekly trend" note="Bars: findings per week across all developers. Lines: 4-week moving average and pooled fix rate (right axis).">
        <TeamTrendChart data={teamTrend(data)} colors={colors} />
      </Section>
      <div className="grid-2">
        <Section title="Research risk profile bands (week 16)" note="Research risk profile based on measured behaviour; not a judgment of the person.">
          <ul className="plain">
            <li><span className="badge band-low">LOW</span> {o.riskBandCounts.LOW} developers</li>
            <li><span className="badge band-medium">MEDIUM</span> {o.riskBandCounts.MEDIUM} developers</li>
            <li><span className="badge band-high">HIGH</span> {o.riskBandCounts.HIGH} developers</li>
          </ul>
        </Section>
        <Section title="Developer trend directions" note="From the slope of each developer's introduction rate per session.">
          <ul className="plain">
            {Object.entries(o.trendDirections).map(([k, v]) => <li key={k}>{k}: {v}</li>)}
          </ul>
        </Section>
      </div>
    </>
  );
}
