import { useState } from "react";
import type { Analytics } from "../types/analytics";
import type { ChartColors } from "../theme/useChartColors";
import { Section, Toggle } from "../components/common";
import { Heatmap } from "../charts/Heatmap";
import { heatmap } from "../data/selectors";

export function Correlations({ data, colors }: { data: Analytics; colors: ChartColors }) {
  const [levelKey, setLevelKey] = useState<"developer" | "week">("developer");
  const [method, setMethod] = useState<"pearson" | "spearman">("pearson");
  const level = data.correlations[levelKey];
  const nSig = level.pairs.filter((p) => p[method].significant).length;
  const finding = data.keyFindings.find((k) => k.topic === "correlation");

  return (
    <Section
      title="Correlations between behaviour metrics"
      note={`${level.note} ${nSig} of ${level.nTests} pairs significant after Benjamini-Hochberg correction (alpha ${level.alpha}). Cells show r and the adjusted p-value; * and an outline mark significant cells.`}
    >
      <div className="controls">
        <Toggle label="Level" value={levelKey} onChange={setLevelKey}
          options={[{ value: "developer", label: "Developer (main)" }, { value: "week", label: "Developer-week (secondary)" }]} />
        <Toggle label="Method" value={method} onChange={setMethod}
          options={[{ value: "pearson", label: "Pearson" }, { value: "spearman", label: "Spearman" }]} />
      </div>
      <Heatmap cells={heatmap(level, method)} labels={data.correlations.variableLabels} colors={colors} />
      <p className="muted small">Blue = positive, red = negative; stronger colour = larger |r|. Correlation is not causation.</p>
      {finding && <p className="small">{finding.text}</p>}
    </Section>
  );
}
