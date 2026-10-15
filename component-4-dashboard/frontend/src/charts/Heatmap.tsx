import type { HeatCell } from "../data/selectors";
import type { ChartColors } from "../theme/useChartColors";
import { num, pValue } from "../data/format";

/**
 * Correlation heatmap as an HTML table (readable by screen readers, scrolls at
 * narrow widths). Colour: blue for positive r, red for negative, opacity |r|.
 * Significant cells (BH-adjusted p < alpha) are outlined and marked with *.
 */
export function Heatmap({ cells, labels, colors }: {
  cells: HeatCell[][]; labels: Record<string, string>; colors: ChartColors;
}) {
  const name = (v: string) => labels[v] ?? v;
  return (
    <div className="table-wrap" role="region" aria-label="Correlation heatmap" tabIndex={0}>
      <table className="heatmap">
        <thead>
          <tr>
            <th scope="col"><span className="sr-only">Variable</span></th>
            {cells[0]?.map((c) => <th key={c.col} scope="col" className="heat-col">{name(c.col)}</th>)}
          </tr>
        </thead>
        <tbody>
          {cells.map((row) => (
            <tr key={row[0].row}>
              <th scope="row">{name(row[0].row)}</th>
              {row.map((cell) => {
                if (cell.diagonal) return <td key={cell.col} className="heat-cell heat-diag">1</td>;
                const r = cell.r ?? 0;
                const color = r >= 0 ? colors.blue : colors.red;
                return (
                  <td
                    key={cell.col}
                    className={`heat-cell${cell.significant ? " heat-sig" : ""}`}
                    style={{ background: `color-mix(in srgb, ${color} ${Math.round(Math.abs(r) * 85)}%, transparent)` }}
                    title={`${name(cell.row)} ~ ${name(cell.col)}: r = ${num(cell.r)}, adjusted p = ${pValue(cell.pAdj)}${cell.significant ? " (significant)" : ""}`}
                  >
                    <div className="heat-r">{num(cell.r)}{cell.significant ? "*" : ""}</div>
                    <div className="heat-p">p<sub>adj</sub> {pValue(cell.pAdj)}</div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
