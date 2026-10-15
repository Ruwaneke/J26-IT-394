import type { ReactNode } from "react";
import type { Band, Meta } from "../types/analytics";
import type { Verdict } from "../data/format";

export function DataBanner({ meta }: { meta: Meta }) {
  const simulated = meta.dataSource === "simulated";
  return (
    <div className={`banner ${simulated ? "banner-sim" : "banner-real"}`} role="note">
      <strong>{simulated ? "Simulated data" : "Component 2 data"}</strong>
      <span>{meta.disclaimer}</span>
      {meta.sample && <span className="muted">Sample: {meta.sample.nDevelopersIncluded} developers. {meta.sample.note}</span>}
      {meta.quick && <span className="muted">Generated in quick (smoke-test) mode.</span>}
    </div>
  );
}

export function Loading() {
  return <div className="state" role="status" aria-live="polite"><span className="spinner" aria-hidden="true" /> Loading analytics…</div>;
}

export function ErrorState({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="state state-error" role="alert">
      <p><strong>Could not load the analytics data.</strong></p>
      <p>{message}</p>
      <button className="button" onClick={onRetry}>Try again</button>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="state">{children}</div>;
}

export function Section({ title, children, note }: { title: string; children: ReactNode; note?: ReactNode }) {
  return (
    <section className="card">
      <h2>{title}</h2>
      {note && <p className="muted small">{note}</p>}
      {children}
    </section>
  );
}

export function Kpi({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="kpi">
      <div className="kpi-value">{value}</div>
      <div className="kpi-label">{label}</div>
      {hint && <div className="muted small">{hint}</div>}
    </div>
  );
}

export function BandBadge({ band }: { band: Band | null }) {
  if (!band) return <span className="muted">–</span>;
  return <span className={`badge band-${band.toLowerCase()}`}>{band}</span>;
}

export function VerdictBadge({ verdict }: { verdict: Verdict | null }) {
  if (!verdict) return <span className="muted">–</span>;
  const text = verdict === "beats" ? "beats" : verdict === "worse" ? "worse" : "ties";
  return <span className={`badge verdict-${verdict}`}>{text}</span>;
}

export function Picker<T extends string>({ label, value, options, onChange, format }: {
  label: string; value: T; options: T[]; onChange: (v: T) => void; format?: (v: T) => string;
}) {
  const id = `picker-${label.replace(/\W+/g, "-").toLowerCase()}`;
  return (
    <label className="picker" htmlFor={id}>
      <span>{label}</span>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value as T)}>
        {options.map((o) => <option key={o} value={o}>{format ? format(o) : o}</option>)}
      </select>
    </label>
  );
}

/** A row of toggle buttons (aria-pressed), e.g. LOW / MEDIUM / HIGH filters. */
export function Toggle<T extends string | number>({ label, value, options, onChange }: {
  label: string; value: T; options: { value: T; label: string }[]; onChange: (v: T) => void;
}) {
  return (
    <div className="toggle" role="group" aria-label={label}>
      <span className="toggle-label">{label}</span>
      {options.map((o) => (
        <button key={String(o.value)} className="toggle-button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function TableWrap({ children, label }: { children: ReactNode; label: string }) {
  return <div className="table-wrap" role="region" aria-label={label} tabIndex={0}>{children}</div>;
}
