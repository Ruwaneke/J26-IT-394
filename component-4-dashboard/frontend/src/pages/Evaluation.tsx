import type { Analytics } from "../types/analytics";
import type { ChartColors } from "../theme/useChartColors";
import { Section, TableWrap, VerdictBadge } from "../components/common";
import { ImportanceChart } from "../charts/charts";
import { forecastVerdict, meanStd, modelLabel, num, pValue } from "../data/format";
import { classifierSignificance } from "../data/selectors";

export function Evaluation({ data, colors }: { data: Analytics; colors: ChartColors }) {
  const fe = data.forecastEvaluation;
  const re = data.riskEvaluation;
  const forecastRows = fe.metrics.filter((m) => m.horizon === "all");
  const models = [...new Set(forecastRows.map((m) => m.model))];
  const metric = (model: string, target: "vulnCount" | "fixRate") => forecastRows.find((m) => m.model === model && m.target === target);
  const ensembles = [...new Set(fe.wilcoxon.map((w) => w.model))];

  return (
    <>
      <Section title="Key findings" note="Generated from the significance tests in the pipeline, so the text always matches the numbers below.">
        <ul className="findings">
          {data.keyFindings.map((k, i) => (
            <li key={i} className={`finding finding-${k.topic}`}><span className="badge">{k.topic}</span> {k.text}</li>
          ))}
        </ul>
      </Section>

      <Section title="Forecasting: test metrics (weeks 13-16, both horizons)" note={`${fe.residualNote} Variant rows show mean ± std over ${fe.seeds.length} seeds; ensembles and baselines are single values. Selection score: ${fe.selectionScore}.`}>
        <TableWrap label="Forecast metrics">
          <table>
            <thead>
              <tr>
                <th scope="col">Model</th>
                <th scope="col">Validation score</th>
                <th scope="col">MAE findings</th>
                <th scope="col">sMAPE findings</th>
                <th scope="col">MAE fix rate</th>
                <th scope="col">sMAPE fix rate</th>
              </tr>
            </thead>
            <tbody>
              {models.map((m) => {
                const v = metric(m, "vulnCount");
                const f = metric(m, "fixRate");
                const sel = fe.selected[m];
                return (
                  <tr key={m} className={m === fe.deployed ? "row-highlight" : undefined}>
                    <th scope="row">
                      {modelLabel(m)}
                      {m === fe.deployed && <span className="badge">deployed</span>}
                      {sel?.targetMode === "residual" && <span className="badge">post-hoc</span>}
                    </th>
                    <td>{sel ? num(sel.valScore, 3) : ""}</td>
                    <td>{meanStd(v?.mae.mean, v?.mae.std)}</td>
                    <td>{meanStd(v?.smape.mean, v?.smape.std, 1)}</td>
                    <td>{meanStd(f?.mae.mean, f?.mae.std)}</td>
                    <td>{meanStd(f?.smape.mean, f?.smape.std, 1)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
        <h3>Wilcoxon signed-rank tests (per-developer MAE, model vs baseline)</h3>
        <TableWrap label="Forecast significance">
          <table>
            <thead>
              <tr><th scope="col">Model</th><th scope="col">Baseline</th><th scope="col">Target</th><th scope="col">Median diff</th><th scope="col">p</th><th scope="col">Verdict</th></tr>
            </thead>
            <tbody>
              {ensembles.flatMap((model) => fe.wilcoxon.filter((w) => w.model === model).map((w) => (
                <tr key={`${model}-${w.baseline}-${w.target}`}>
                  <th scope="row">{modelLabel(model)}</th>
                  <td>{modelLabel(w.baseline)}</td>
                  <td>{w.target === "vulnCount" ? "findings" : "fix rate"}</td>
                  <td>{num(w.medianDiff, 3)}</td>
                  <td>{pValue(w.pValue)}</td>
                  <td><VerdictBadge verdict={forecastVerdict(w.pValue, w.medianDiff)} /></td>
                </tr>
              )))}
            </tbody>
          </table>
        </TableWrap>
      </Section>

      <Section title="Risk classification: headline" note={`${re.headlineMethod}. ${re.postHocNote}`}>
        <TableWrap label="Classifier headline">
          <table>
            <thead>
              <tr><th scope="col">Model</th><th scope="col">Macro F1 (mean ± std)</th><th scope="col">95% CI</th><th scope="col">Accuracy</th><th scope="col">HIGH recall</th></tr>
            </thead>
            <tbody>
              {re.headline.map((h) => (
                <tr key={h.model}>
                  <th scope="row">{modelLabel(h.model)}</th>
                  <td>{meanStd(h.macroF1.mean, h.macroF1.std)}</td>
                  <td>[{num(h.macroF1.ciLow, 3)}, {num(h.macroF1.ciHigh, 3)}]</td>
                  <td>{num(h.accuracy.mean, 3)}</td>
                  <td>{num(h.recallHigh.mean, 3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
        <h3>XGBoost vs each baseline (paired developer-level bootstrap)</h3>
        <TableWrap label="Classifier significance">
          <table>
            <thead>
              <tr><th scope="col">Baseline</th><th scope="col">Macro-F1 difference</th><th scope="col">95% CI</th><th scope="col">P(XGBoost better)</th><th scope="col">Verdict</th><th scope="col">McNemar p (secondary)</th></tr>
            </thead>
            <tbody>
              {classifierSignificance(data).map((s) => (
                <tr key={s.baseline}>
                  <th scope="row">{modelLabel(s.baseline)}</th>
                  <td>{num(s.bootstrapMacroF1Diff.meanDiff, 3)}</td>
                  <td>[{num(s.bootstrapMacroF1Diff.ciLow, 3)}, {num(s.bootstrapMacroF1Diff.ciHigh, 3)}]</td>
                  <td>{num(s.bootstrapMacroF1Diff.xgbBetterShare, 2)}</td>
                  <td><VerdictBadge verdict={s.verdict} /></td>
                  <td>{pValue(s.mcnemarRepeat1.pValue)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
        <p className="muted small">{re.significance[0]?.mcnemarRepeat1.note}</p>
        <h3>Round 1: 12 held-out developers (already seen)</h3>
        <p className="muted small">{re.round1.note}</p>
        <TableWrap label="Round 1 results">
          <table>
            <thead><tr><th scope="col">Model</th><th scope="col">Macro F1, original features</th><th scope="col">Macro F1, extended features</th></tr></thead>
            <tbody>
              {re.round1.originalFeatures.map((r) => (
                <tr key={r.model}>
                  <th scope="row">{modelLabel(r.model)}</th>
                  <td>{num(r.macroF1, 3)}</td>
                  <td>{num(re.round1.extendedFeatures.find((x) => x.model === r.model)?.macroF1, 3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Section>

      <Section title="Global feature importance (XGBoost, mean |SHAP|)" note={re.featureImportanceNote}>
        <ImportanceChart data={re.featureImportance.slice(0, 12)} colors={colors} />
      </Section>
    </>
  );
}
