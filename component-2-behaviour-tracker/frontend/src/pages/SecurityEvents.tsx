import React, { useState, useId } from 'react';
import { useParams, Link } from 'react-router';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import {
  PageHeader,
  Card,
  LoadingState,
  ErrorState,
  EmptyState,
  formatDateTime,
  splitFilePath,
} from '../components/Cards';
import { StatusBadge, SeverityBadge, STATUS_CONFIG, SEVERITY_CONFIG } from '../components/Badges';
import { Icon } from '../components/Icon';
import { SecurityEvent, SecurityEventStatus, Severity } from '../types';

const STATUS_KEYS: SecurityEventStatus[] = ['DETECTED', 'OPENED', 'FIXED', 'IGNORED', 'REOPENED'];
const SEVERITY_KEYS: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export const SecurityEvents: React.FC = () => {
  const { developerId } = useParams<{ developerId: string }>();
  const id = developerId ? parseInt(developerId, 10) : 0;

  const eventsApi = useApi(`events:${id}`, signal => api.getSecurityEvents(id, signal));

  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [sortField, setSortField] = useState<keyof SecurityEvent>('detectedAt');
  const [sortDirection, setSortDirection] = useState<'ascending' | 'descending'>('descending');
  const selectId = useId();

  if (eventsApi.error) {
    return <ErrorState error={eventsApi.error} onRetry={eventsApi.reload} />;
  }

  if (eventsApi.loading || !eventsApi.data) {
    return <LoadingState />;
  }

  const events: SecurityEvent[] = eventsApi.data;

  // Status counts
  const counts = new Map<SecurityEventStatus, number>();
  for (const ev of events) {
    counts.set(ev.currentStatus, (counts.get(ev.currentStatus) || 0) + 1);
  }

  const filtered = events
    .filter(e => (statusFilter === 'ALL' ? true : e.currentStatus === statusFilter))
    .filter(e => (severityFilter === 'ALL' ? true : e.severity === severityFilter))
    .sort((a, b) => {
      let cmp = 0;
      if (sortField === 'detectedAt') {
        cmp = new Date(a.detectedAt).getTime() - new Date(b.detectedAt).getTime();
      } else if (sortField === 'lineNumber') {
        cmp = a.lineNumber - b.lineNumber;
      } else if (sortField === 'severity') {
        cmp = (SEVERITY_CONFIG[a.severity]?.level || 0) - (SEVERITY_CONFIG[b.severity]?.level || 0);
      } else if (sortField === 'vulnerabilityType') {
        cmp = a.vulnerabilityType.localeCompare(b.vulnerabilityType);
      } else if (sortField === 'fileName') {
        cmp = splitFilePath(a.fileName).name.localeCompare(splitFilePath(b.fileName).name);
      }
      return sortDirection === 'ascending' ? cmp : -cmp;
    });

  const toggleSort = (field: keyof SecurityEvent) => {
    if (sortField === field) {
      setSortDirection(prev => (prev === 'ascending' ? 'descending' : 'ascending'));
    } else {
      setSortField(field);
      setSortDirection(field === 'detectedAt' || field === 'severity' ? 'descending' : 'ascending');
    }
  };

  return (
    <>
      <PageHeader
        title="Security Event Monitoring"
        description="Every vulnerability detected in this developer’s code, with its file location, severity level, and current lifecycle status."
        endpoints={[`/api/security-events/developer/${id}`]}
      />

      {events.length === 0 ? (
        <EmptyState title="No security events yet">
          Events appear here when Sentinel detects a vulnerability in code worked on by this developer.
        </EmptyState>
      ) : (
        <Card
          title={`Security Events (${events.length})`}
          description="Select a column heading to sort. Click timeline to follow a vulnerability through its full lifecycle."
        >
          <div className="toolbar">
            <div className="segmented" role="group" aria-label="Filter by status">
              <button
                type="button"
                className="chip"
                aria-pressed={statusFilter === 'ALL'}
                onClick={() => setStatusFilter('ALL')}
              >
                All statuses <span className="chip-count">{events.length}</span>
              </button>
              {STATUS_KEYS.filter(s => counts.has(s)).map(status => {
                const conf = STATUS_CONFIG[status];
                return (
                  <button
                    key={status}
                    type="button"
                    className={`chip tone-${conf.tone}`}
                    aria-pressed={statusFilter === status}
                    onClick={() => setStatusFilter(status)}
                  >
                    <Icon name={conf.icon} size={14} className="badge-icon" />
                    {conf.label}
                    <span className="chip-count">{counts.get(status)}</span>
                  </button>
                );
              })}
            </div>

            <div className="select-field">
              <label htmlFor={selectId}>Severity</label>
              <select
                id={selectId}
                className="select"
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
              >
                <option value="ALL">All severities</option>
                {SEVERITY_KEYS.map(sev => (
                  <option key={sev} value={sev}>
                    {SEVERITY_CONFIG[sev].label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {filtered.length === 0 ? (
            <EmptyState title="No security events match these filters">
              <button
                type="button"
                className="button"
                onClick={() => {
                  setStatusFilter('ALL');
                  setSeverityFilter('ALL');
                }}
              >
                Clear filters
              </button>
            </EmptyState>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th scope="col">
                      <button
                        type="button"
                        className="sort-button"
                        onClick={() => toggleSort('vulnerabilityType')}
                      >
                        Vulnerability Type
                        <Icon
                          name={
                            sortField === 'vulnerabilityType'
                              ? sortDirection === 'ascending'
                                ? 'sortUp'
                                : 'sortDown'
                              : 'sortNone'
                          }
                          size={14}
                        />
                      </button>
                    </th>
                    <th scope="col">
                      <button type="button" className="sort-button" onClick={() => toggleSort('severity')}>
                        Severity
                        <Icon
                          name={
                            sortField === 'severity'
                              ? sortDirection === 'ascending'
                                ? 'sortUp'
                                : 'sortDown'
                              : 'sortNone'
                          }
                          size={14}
                        />
                      </button>
                    </th>
                    <th scope="col">
                      <button type="button" className="sort-button" onClick={() => toggleSort('fileName')}>
                        File Name
                        <Icon
                          name={
                            sortField === 'fileName'
                              ? sortDirection === 'ascending'
                                ? 'sortUp'
                                : 'sortDown'
                              : 'sortNone'
                          }
                          size={14}
                        />
                      </button>
                    </th>
                    <th scope="col" className="num">
                      <button
                        type="button"
                        className="sort-button"
                        onClick={() => toggleSort('lineNumber')}
                      >
                        Line
                        <Icon
                          name={
                            sortField === 'lineNumber'
                              ? sortDirection === 'ascending'
                                ? 'sortUp'
                                : 'sortDown'
                              : 'sortNone'
                          }
                          size={14}
                        />
                      </button>
                    </th>
                    <th scope="col">Status</th>
                    <th scope="col">
                      <button
                        type="button"
                        className="sort-button"
                        onClick={() => toggleSort('detectedAt')}
                      >
                        Detected Time
                        <Icon
                          name={
                            sortField === 'detectedAt'
                              ? sortDirection === 'ascending'
                                ? 'sortUp'
                                : 'sortDown'
                              : 'sortNone'
                          }
                          size={14}
                        />
                      </button>
                    </th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(ev => {
                    const file = splitFilePath(ev.fileName);
                    return (
                      <tr key={ev.id}>
                        <td>
                          <div className="cell-title mono">{ev.vulnerabilityType}</div>
                          <div className="cell-sub">
                            #{ev.id} · {ev.message}
                          </div>
                        </td>
                        <td>
                          <SeverityBadge severity={ev.severity} />
                        </td>
                        <td>
                          <div className="cell-title mono">{file.name}</div>
                          {file.directory && <div className="cell-sub mono">{file.directory}</div>}
                        </td>
                        <td className="num">{ev.lineNumber}</td>
                        <td>
                          <StatusBadge status={ev.currentStatus} />
                        </td>
                        <td className="nowrap">
                          <time dateTime={ev.detectedAt}>{formatDateTime(ev.detectedAt)}</time>
                        </td>
                        <td>
                          <Link
                            to={`/developers/${id}/lifecycle?event=${ev.id}`}
                            className="row-link"
                          >
                            Timeline <Icon name="arrowRight" size={14} />
                          </Link>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </>
  );
};
