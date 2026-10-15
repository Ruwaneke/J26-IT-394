import {
  Area, Bar, BarChart, CartesianGrid, ComposedChart, Legend, Line, ReferenceLine, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from "recharts";
import type { ChartColors } from "../theme/useChartColors";
import type { ForecastRow } from "../data/selectors";
import { isNum } from "../data/format";

function common(c: ChartColors) {
  return {
    grid: <CartesianGrid stroke={c.grid} strokeDasharray="3 3" />,
    tooltip: (
      <Tooltip
        contentStyle={{ background: c.bg, border: `1px solid ${c.grid}`, color: c.fg }}
        labelStyle={{ color: c.fg }}
        labelFormatter={(w) => `Week ${w}`}
      />
    ),
    legend: <Legend wrapperStyle={{ color: c.fg, fontSize: 12 }} />,
    tick: { fill: c.muted, fontSize: 12 },
  };
}

const pctTick = (v: number) => `${Math.round(v * 100)}%`;
const fmt = (digits: number) => (v: unknown) => (isNum(v) ? v.toFixed(digits) : "–");
const fmtPct = (v: unknown) => (isNum(v) ? `${(v * 100).toFixed(0)}%` : "–");

type TeamRow = { week: number; vulnCount: number; vulnCountMa4: number | null; fixRate: number | null };

export function TeamTrendChart({ data, colors }: { data: TeamRow[]; colors: ChartColors }) {
  const c = common(colors);
  return (
    <div className="chart" role="img" aria-label="Team weekly findings with 4-week moving average and fix rate">
      <ResponsiveContainer width="100%" height={300}>
        <ComposedChart data={data} margin={{ top: 8, right: 8, bottom: 8, left: 0 }}>
          {c.grid}
          <XAxis dataKey="week" tick={c.tick} />
          <YAxis yAxisId="count" tick={c.tick} width={40} />
          <YAxis yAxisId="rate" orientation="right" tick={c.tick} domain={[0, 1]} tickFormatter={pctTick} width={44} />
          {c.tooltip}
          {c.legend}
          <Bar isAnimationActive={false} yAxisId="count" dataKey="vulnCount" name="Findings" fill={colors.blue} fillOpacity={0.55} />
          <Line isAnimationActive={false} yAxisId="count" dataKey="vulnCountMa4" name="4-week average" stroke={colors.blue} strokeWidth={2} dot={false} />
          <Line isAnimationActive={false} yAxisId="rate" dataKey="fixRate" name="Fix rate" stroke={colors.green} strokeWidth={2} dot={false} formatter={fmtPct} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}

type DevRow = { week: number; introRate: number | null; teamIntroRate: number | null };

export function DeveloperTrendChart({ data, colors }: { data: DevRow[]; colors: ChartColors }) {
  const c = common(colors);
  return (
    <div className="chart" role="img" aria-label="Developer weekly vulnerability introduction rate per session compared with the team">
      <ResponsiveContainer width="100%" height={300}>
        <ComposedChart data={data} margin={{ top: 8, right: 8, bottom: 8, left: 0 }}>
          {c.grid}
          <XAxis dataKey="week" tick={c.tick} />
          <YAxis tick={c.tick} width={40} label={{ value: "per session", angle: -90, position: "insideLeft", fill: colors.muted, fontSize: 12 }} />
          {c.tooltip}
          {c.legend}
          <Line isAnimationActive={false} dataKey="introRate" name="Developer (active weeks)" stroke={colors.orange} strokeWidth={2} connectNulls={false} formatter={fmt(2)} />
          <Line isAnimationActive={false} dataKey="teamIntroRate" name="Team" stroke={colors.muted} strokeDasharray="5 4" dot={false} formatter={fmt(2)} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ForecastChart({ data, colors, isRate, testStart, deployedLabel }: {
  data: ForecastRow[]; colors: ChartColors; isRate: boolean; testStart: number; deployedLabel: string;
}) {
  const c = common(colors);
  const f = isRate ? fmtPct : fmt(1);
  const lastHistory = Math.max(...data.filter((r) => r.actual !== null).map((r) => r.week), 0);
  return (
    <div className="chart" role="img" aria-label="Forecast: history, test-period predictions and future weeks with seed spread">
      <ResponsiveContainer width="100%" height={320}>
        <ComposedChart data={data} margin={{ top: 8, right: 8, bottom: 8, left: 0 }}>
          {c.grid}
          <XAxis dataKey="week" tick={c.tick} type="number" domain={["dataMin", "dataMax"]} allowDecimals={false} />
          <YAxis tick={c.tick} width={44} domain={isRate ? [0, 1] : [0, "auto"]} tickFormatter={isRate ? pctTick : undefined} />
          {c.tooltip}
          {c.legend}
          <ReferenceLine x={testStart - 0.5} stroke={colors.muted} strokeDasharray="2 4" label={{ value: "test", fill: colors.muted, fontSize: 11, position: "insideTopRight" }} />
          {lastHistory > 0 && <ReferenceLine x={lastHistory + 0.5} stroke={colors.muted} strokeDasharray="2 4" label={{ value: "future", fill: colors.muted, fontSize: 11, position: "insideTopRight" }} />}
          <Area dataKey="band" name="Seed spread (not a calibrated CI)" stroke="none" fill={colors.purple} fillOpacity={0.25} connectNulls={false} />
          <Line isAnimationActive={false} dataKey="actual" name="Actual" stroke={colors.fg} strokeWidth={2} connectNulls={false} formatter={f} />
          <Line isAnimationActive={false} dataKey="predicted" name={`${deployedLabel} (test)`} stroke={colors.orange} strokeWidth={2} formatter={f} />
          <Line isAnimationActive={false} dataKey="mean4" name="4-week mean (test)" stroke={colors.green} strokeDasharray="4 3" formatter={f} />
          <Line isAnimationActive={false} dataKey="futureMean" name="Forecast weeks 17-18" stroke={colors.purple} strokeWidth={2} strokeDasharray="6 3" formatter={f} />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ImportanceChart({ data, colors }: { data: { feature: string; meanAbsShap: number }[]; colors: ChartColors }) {
  const c = common(colors);
  return (
    <div className="chart" role="img" aria-label="Global feature importance, mean absolute SHAP">
      <ResponsiveContainer width="100%" height={Math.max(220, data.length * 26)}>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, bottom: 4, left: 8 }}>
          {c.grid}
          <XAxis type="number" tick={c.tick} />
          <YAxis type="category" dataKey="feature" tick={c.tick} width={170} />
          <Tooltip contentStyle={{ background: colors.bg, border: `1px solid ${colors.grid}`, color: colors.fg }} formatter={fmt(3)} />
          <Bar isAnimationActive={false} dataKey="meanAbsShap" name="mean |SHAP|" fill={colors.blue} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
