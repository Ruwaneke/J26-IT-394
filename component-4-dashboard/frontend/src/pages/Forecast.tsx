import { useState } from "react";
import type { Analytics, Target } from "../types/analytics";
import type { ChartColors } from "../theme/useChartColors";
import { Empty, Picker, Section, TableWrap, Toggle, VerdictBadge } from "../components/common";
import { ForecastChart } from "../charts/charts";
import { modelLabel, num, pct, pValue } from "../data/format";
import { forecastComparison, forecastSeries } from "../data/selectors";

export function Forecast({ data, colors }: { data: Analytics; colors: ChartColors }) {
  const ids = data.forecast.developers.map((d) => d.developerId).sort();
  const [dev, setDev] = useState(ids[0] ?? "");
  const [target, setTarget] = useState<Target>("vulnCount");
  const [horizon, setHorizon] = useState(1);
  const ev = data.forecastEvaluation;
  const series = forecastSeries(data, dev, target, horizon);
  const deployedLabel = modelLabel(data.forecast.deployed);
  const testStart = Math.min(...ev.split.test.targetWeeks);
  if (!ids.length) return <Empty>No forecasts in this file.</Empty>;

  return (
    <>
      <Section
        title="Forecast per developer"
        note={`Weeks 1-16: actual values. Test weeks ${testStart}-16: ${deployedLabel} (deployed, chosen on validation) and the 4-week-mean baseline, predicted ${horizon} week(s) ahead. Weeks 17-18: forecast with the band showing the ${data.forecast.bandNote}.`}
      >
        <div className="controls">
          <Picker label="Developer" value={dev} options={ids} onChange={setDev} />
          <Toggle label="Target" value={target} onChange={setTarget}
            options={[{ value: "vulnCount", label: "Findings per week" }, { value: "fixRate", label: "Fix rate" }]} />
          <Toggle label="Horizon" value={horizon} onChange={setHorizon}
            options={[{ value: 1, label: "1 week ahead" }, { value: 2, label: "2 weeks ahead" }]} />
        </div>
        {series ? (
          <ForecastChart data={series} colors={colors} isRate={target === "fixRate"} testStart={testStart} deployedLabel={deployedLabel} />
        ) : <Empty>No forecast for {dev}.</Empty>}
        <p className="muted small band-note">Band = {data.forecast.bandNote}. Inactive weeks have no actual value.</p>
      </Section>
      <Section
        title={`${deployedLabel} vs baselines (test weeks ${ev.split.test.targetWeeks.join(", ")})`}
        note="MAE over all test targets and both horizons. Wilcoxon signed-rank test on per-developer MAE, deployed model vs each baseline; 'beats' needs p < 0.05 and a lower median error."
      >
        <TableWrap label="Forecast comparison">
          <table>
            <thead>
              <tr>
                <th scope="col">Model</th>
                <th scope="col">MAE findings/week</th>
                <th scope="col">MAE fix rate</th>
                <th scope="col">Wilcoxon p (findings)</th>
                <th scope="col">Wilcoxon p (fix rate)</th>
                <th scope="col">{deployedLabel} vs this baseline</th>
              </tr>
            </thead>
            <tbody>
              {forecastComparison(data).map((r) => (
                <tr key={r.model}>
                  <th scope="row">{modelLabel(r.model)}</th>
                  <td>{num(r.maeVuln, 3)}</td>
                  <td>{num(r.maeFix, 3)} <span className="muted small">({pct(r.maeFix, 1)} pts)</span></td>
                  <td>{pValue(r.pVuln)}</td>
                  <td>{pValue(r.pFix)}</td>
                  <td>
                    {r.verdictVuln ? (
                      <>findings <VerdictBadge verdict={r.verdictVuln} /> · fix rate <VerdictBadge verdict={r.verdictFix} /></>
                    ) : <span className="muted">deployed model</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Section>
    </>
  );
}
