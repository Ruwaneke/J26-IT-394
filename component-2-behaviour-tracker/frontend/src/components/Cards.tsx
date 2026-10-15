import React, { useId } from 'react';
import { Icon } from './Icon';

export function parseIsoDate(iso: string): Date {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?$/.exec(iso);
  if (!match) return new Date(iso);
  const ms = match[7] ? Number(match[7].slice(0, 3).padEnd(3, '0')) : 0;
  return new Date(+match[1], +match[2] - 1, +match[3], +match[4], +match[5], match[6] ? +match[6] : 0, ms);
}

const dtFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
const dFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
const pctFmt = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });
const numFmt = new Intl.NumberFormat();

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = parseIsoDate(iso);
  return Number.isNaN(d.getTime()) ? iso : dtFmt.format(d);
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = parseIsoDate(iso);
  return Number.isNaN(d.getTime()) ? iso : dFmt.format(d);
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds)) return '—';
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return s % 60 ? `${m}m ${s % 60}s` : `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return m % 60 ? `${h}h ${m % 60}m` : `${h}h`;
  const d = Math.floor(h / 24);
  return h % 24 ? `${d}d ${h % 24}h` : `${d}d`;
}

export function formatPercent(rate: number | null | undefined): string {
  return rate == null ? 'N/A' : `${pctFmt.format(rate)}%`;
}

export function formatNumber(num: number | null | undefined): string {
  return num == null ? '0' : numFmt.format(num);
}

export function splitFilePath(filePath: string): { name: string; directory: string } {
  const slash = Math.max(filePath.lastIndexOf('/'), filePath.lastIndexOf('\\'));
  return slash < 0
    ? { name: filePath, directory: '' }
    : { name: filePath.slice(slash + 1), directory: filePath.slice(0, slash + 1) };
}

export const Card: React.FC<{
  title?: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
  children: React.ReactNode;
}> = ({ title, description, actions, className, children }) => {
  const id = useId();
  return (
    <section className={className ? `card ${className}` : 'card'} aria-labelledby={title ? id : undefined}>
      {(title || actions) && (
        <div className="card-header">
          <div>
            {title && (
              <h2 id={id} className="card-title">
                {title}
              </h2>
            )}
            {description && <p className="card-description">{description}</p>}
          </div>
          {actions}
        </div>
      )}
      {children}
    </section>
  );
};

export const StatTile: React.FC<{
  label: string;
  value: React.ReactNode;
  detail?: React.ReactNode;
  icon?: string;
}> = ({ label, value, detail, icon }) => (
  <div className="card stat-tile">
    <div className="stat-label">
      {icon && <Icon name={icon} size={15} />}
      {label}
    </div>
    <div className="stat-value">{value}</div>
    {detail && <div className="stat-detail">{detail}</div>}
  </div>
);

export const Meter: React.FC<{
  label: string;
  value: number | null;
  detail?: React.ReactNode;
  higherIsBetter?: boolean;
}> = ({ label, value, detail, higherIsBetter }) => {
  const fill = value == null ? 0 : Math.min(100, Math.max(0, value));
  return (
    <div className="card meter">
      <div className="meter-head">
        <div>
          <span className="meter-label">{label}</span>
          <span className="meter-direction">
            {higherIsBetter ? 'Higher is better' : 'Lower is better'}
          </span>
        </div>
        <span className="meter-value">{formatPercent(value)}</span>
      </div>
      {value == null ? (
        <div className="meter-track is-empty" />
      ) : (
        <div
          className="meter-track"
          role="meter"
          aria-label={label}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={value}
          aria-valuetext={formatPercent(value)}
        >
          {fill > 0 && <div className="meter-fill" style={{ width: `${fill}%` }} />}
        </div>
      )}
      {detail && <div className="meter-foot">{detail}</div>}
    </div>
  );
};

export const PageHeader: React.FC<{
  title: string;
  description: string;
  endpoints?: string[];
}> = ({ title, description, endpoints = [] }) => (
  <header className="page-header">
    <h1>{title}</h1>
    <p className="page-description">{description}</p>
    {endpoints.length > 0 && (
      <p className="page-source">
        <Icon name="link" size={13} />
        <span>Data from</span>
        {endpoints.map(e => (
          <code key={e}>GET {e}</code>
        ))}
      </p>
    )}
  </header>
);

export const LoadingState: React.FC = () => (
  <div className="state state-loading" role="status">
    <div className="spinner" />
    <span>Loading…</span>
  </div>
);

export const ErrorState: React.FC<{
  error: Error;
  onRetry?: () => void;
}> = ({ error, onRetry }) => (
  <div className="state state-error" role="alert">
    <Icon name="error" size={20} className="state-icon" />
    <div className="state-body">
      <strong>Error loading data</strong>
      <p>{error.message}</p>
      {onRetry && (
        <button type="button" className="button" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  </div>
);

export const EmptyState: React.FC<{
  title: string;
  children?: React.ReactNode;
}> = ({ title, children }) => (
  <div className="state state-empty">
    <Icon name="info" size={20} className="state-icon" />
    <div className="state-body">
      <strong>{title}</strong>
      {children && <p>{children}</p>}
    </div>
  </div>
);
