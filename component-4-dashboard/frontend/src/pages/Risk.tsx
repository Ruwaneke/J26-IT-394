import { useState } from "react";
import type { Analytics, Band } from "../types/analytics";
import { BandBadge, Empty, Section, TableWrap, Toggle } from "../components/common";
import { pct } from "../data/format";
import { riskRows, type RiskSortKey } from "../data/selectors";

const COLUMNS: { key: RiskSortKey; label: string }[] = [
  { key: "developerId", label: "Developer" },
  { key: "band", label: "Band" },
  { key: "LOW", label: "P(LOW)" },
  { key: "MEDIUM", label: "P(MEDIUM)" },
  { key: "HIGH", label: "P(HIGH)" },
];

export function Risk({ data }: { data: Analytics }) {
  const [filter, setFilter] = useState<Band | "ALL">("ALL");
  const [sortKey, setSortKey] = useState<RiskSortKey>("band");
  const [desc, setDesc] = useState(true);
  const rows = riskRows(data, filter, sortKey, desc);
  const r = data.risk;

  const sortBy = (key: RiskSortKey) => {
    if (key === sortKey) setDesc(!desc);
    else { setSortKey(key); setDesc(key !== "developerId"); }
  };

  return (
    <Section
      title="Research risk profile based on measured behaviour"
      note={`${r.framing} Scored at week ${r.scoredAtWeek} for weeks ${r.predictsWeeks.join("-")}. ${r.driversNote}`}
    >
      <div className="controls">
        <Toggle label="Band" value={filter} onChange={setFilter}
          options={[{ value: "ALL", label: "All" }, { value: "LOW", label: "LOW" }, { value: "MEDIUM", label: "MEDIUM" }, { value: "HIGH", label: "HIGH" }]} />
        <span className="muted small" aria-live="polite">{rows.length} developers</span>
      </div>
      {rows.length === 0 ? <Empty>No developers in this band.</Empty> : (
        <TableWrap label="Risk profiles">
          <table className="risk-table">
            <thead>
              <tr>
                {COLUMNS.map((c) => (
                  <th key={c.key} scope="col" aria-sort={sortKey === c.key ? (desc ? "descending" : "ascending") : "none"}>
                    <button className="sort" onClick={() => sortBy(c.key)}>
                      {c.label}{sortKey === c.key ? (desc ? " ▼" : " ▲") : ""}
                    </button>
                  </th>
                ))}
                <th scope="col">Measured-behaviour reasons (weeks 13-16 vs study median)</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.developerId}>
                  <th scope="row">{d.developerId}</th>
                  <td data-label="Band"><BandBadge band={d.band} /></td>
                  <td data-label="P(LOW)">{pct(d.probabilities.LOW)}</td>
                  <td data-label="P(MEDIUM)">{pct(d.probabilities.MEDIUM)}</td>
                  <td data-label="P(HIGH)">{pct(d.probabilities.HIGH)}</td>
                  <td className="reasons-cell">
                    {d.drivers.length ? (
                      <ul className="reasons">{d.drivers.map((x) => <li key={x.metric} className={`reason-${x.direction}`}>{x.text}</li>)}</ul>
                    ) : <span className="muted">No measured metric stands out from the study median.</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Section>
  );
}
