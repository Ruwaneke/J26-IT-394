import { useState } from "react";
import type { Analytics } from "../types/analytics";
import { BandBadge, Empty, Section, Toggle } from "../components/common";
import { recommendationRows } from "../data/selectors";

const PRIORITY_TEXT: Record<number, string> = { 1: "Priority 1 (most urgent)", 2: "Priority 2", 3: "Priority 3" };

export function Recommendations({ data }: { data: Analytics }) {
  const [priority, setPriority] = useState<0 | 1 | 2 | 3>(0);
  const rows = recommendationRows(data, priority);
  return (
    <Section
      title="Recommendations"
      note={`${data.recommendations.framing} Rules are configured in ml/config.yaml; each developer gets up to 3 recommendations, and all fired rule ids are listed.`}
    >
      <div className="controls">
        <Toggle label="Priority" value={priority} onChange={setPriority}
          options={[{ value: 0, label: "All" }, { value: 1, label: "1" }, { value: 2, label: "2" }, { value: 3, label: "3" }]} />
        <span className="muted small" aria-live="polite">{rows.length} developers</span>
      </div>
      {rows.length === 0 ? <Empty>No developers with this priority.</Empty> : (
        <ul className="rec-list">
          {rows.map((d) => (
            <li key={d.developerId} className={`rec rec-p${d.priority}`}>
              <div className="rec-head">
                <strong>{d.developerId}</strong>
                <span className={`badge priority-${d.priority}`}>{PRIORITY_TEXT[d.priority]}</span>
                <BandBadge band={d.band} />
                <span className="rules" aria-label="Rules fired">{d.firedRules.map((r) => <code key={r}>{r}</code>)}</span>
              </div>
              <ol>
                {d.recommendations.map((r) => (
                  <li key={r.ruleId}><code>{r.ruleId}</code> {r.text}</li>
                ))}
              </ol>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}
