/**
 * Sentinel — small inline-SVG / HTML chart helpers shared by the dashboards.
 *
 * Detected/Fixed series colours (#d97706 / #3b82f6) were validated with the dataviz palette
 * checker on both the dark (#111827) and light (#ffffff) surfaces.
 */

import { DailyTrendPoint } from '../analytics/developerInsights.js';

export const C_DETECTED = '#d97706';
export const C_FIXED = '#3b82f6';

/** CSS needed by the helpers below (uses theme tokens). */
export const CHART_CSS = `
.bar-list { display: flex; flex-direction: column; gap: 9px; }
.bar-row { display: grid; grid-template-columns: minmax(110px, 36%) 1fr auto; align-items: center; gap: 10px; font-size: 0.78em; padding: 2px 0; }
.bar-row:hover .bar-track { background: rgba(var(--ink), 0.09); }
.bar-label { color: var(--text-1); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: flex; align-items: center; gap: 6px; }
.bar-track { height: 8px; background: rgba(var(--ink), 0.05); border-radius: 0 4px 4px 0; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 0 4px 4px 0; }
.bar-value { color: var(--text-1); font-weight: 600; white-space: nowrap; text-align: right; min-width: 56px; }
.bar-value .muted { color: var(--text-3); font-weight: 500; }
.sev-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
.chart-head { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 10px; }
.legend { display: flex; gap: 14px; font-size: 0.74em; color: var(--text-1); }
.legend > span { display: inline-flex; align-items: center; gap: 6px; }
.legend-swatch { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
.trend-svg { width: 100%; height: auto; display: block; }
.trend-svg .grid-line { stroke: rgba(var(--ink), 0.07); stroke-width: 1; }
.trend-svg .axis-text { fill: var(--text-3); font-size: 10px; font-family: inherit; }
.trend-svg .hit { fill: transparent; }
.trend-svg .trend-group:hover .hit { fill: rgba(var(--ink), 0.04); }
`;

export function barRowHtml(labelHtml: string, value: number, max: number, valueHtml: string, color: string, tooltip: string): string {
  const w = max > 0 && value > 0 ? Math.max(2, (value / max) * 100) : 0;
  return `<div class="bar-row" title="${escAttr(tooltip)}">
    <div class="bar-label">${labelHtml}</div>
    <div class="bar-track"><div class="bar-fill" style="width:${w}%;background:${color}"></div></div>
    <div class="bar-value">${valueHtml}</div>
  </div>`;
}

/** Grouped bar chart: detected vs fixed per day. */
export function trendChartSvg(trend: DailyTrendPoint[]): string {
  const max = Math.max(1, ...trend.map(t => Math.max(t.detected, t.fixed)));
  const W = 700, H = 220, padL = 32, padB = 26, padT = 10;
  const plotW = W - padL - 8, plotH = H - padB - padT;
  const groupW = trend.length ? plotW / trend.length : plotW;
  const barW = Math.max(4, Math.min(14, (groupW - 10) / 2));
  const yOf = (v: number) => padT + plotH - (v / max) * plotH;
  const bar = (x: number, v: number) => {
    if (v <= 0) { return ''; }
    const y = yOf(v), base = padT + plotH, r = Math.min(4, barW / 2, base - y);
    return `M${x},${base} V${y + r} Q${x},${y} ${x + r},${y} H${x + barW - r} Q${x + barW},${y} ${x + barW},${y + r} V${base} Z`;
  };
  const grid = [0, Math.round(max / 2), max].filter((v, i, a) => a.indexOf(v) === i);
  return `<svg class="trend-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="Detected versus fixed per day">
    ${grid.map(v => `<line x1="${padL}" x2="${W - 8}" y1="${yOf(v)}" y2="${yOf(v)}" class="grid-line"/><text x="${padL - 6}" y="${yOf(v) + 3}" class="axis-text" text-anchor="end">${v}</text>`).join('')}
    ${trend.map((t, i) => {
      const gx = padL + i * groupW;
      const x1 = gx + (groupW - (barW * 2 + 2)) / 2;
      const label = new Date(t.date + 'T00:00:00').toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
      return `<g class="trend-group">
        <rect x="${gx}" y="${padT}" width="${groupW}" height="${plotH}" class="hit"><title>${label} — Detected: ${t.detected} · Fixed: ${t.fixed}</title></rect>
        <path d="${bar(x1, t.detected)}" fill="${C_DETECTED}" pointer-events="none"/>
        <path d="${bar(x1 + barW + 2, t.fixed)}" fill="${C_FIXED}" pointer-events="none"/>
        ${i % 2 === 0 ? `<text x="${gx + groupW / 2}" y="${H - 8}" class="axis-text" text-anchor="middle">${label}</text>` : ''}
      </g>`;
    }).join('')}
  </svg>`;
}

export function trendLegendHtml(trend: DailyTrendPoint[]): string {
  const d = trend.reduce((a, t) => a + t.detected, 0);
  const f = trend.reduce((a, t) => a + t.fixed, 0);
  return `<div class="legend">
    <span><span class="legend-swatch" style="background:${C_DETECTED}"></span>Detected (${d})</span>
    <span><span class="legend-swatch" style="background:${C_FIXED}"></span>Fixed (${f})</span>
  </div>`;
}

function escAttr(s: string): string {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}
