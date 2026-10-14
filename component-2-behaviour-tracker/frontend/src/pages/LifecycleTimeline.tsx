import React, { useState, useEffect } from 'react';
import { useParams, useSearchParams } from 'react-router';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import {
  PageHeader,
  Card,
  LoadingState,
  ErrorState,
  EmptyState,
  formatDateTime,
  formatDuration,
  splitFilePath,
} from '../components/Cards';
import { StatusBadge, SeverityBadge, STATUS_CONFIG } from '../components/Badges';
import { Icon } from '../components/Icon';
import { SecurityEvent, LifecycleHistory, SecurityEventStatus } from '../types';

interface TimelineStep {
  key: string;
  status: SecurityEventStatus;
  previous: SecurityEventStatus | null;
  at: string;
  by: string | null;
  fromEventRecord: boolean;
  sincePrevious: number | null;
}

export const LifecycleTimeline: React.FC = () => {
  const { developerId } = useParams<{ developerId: string }>();
  const id = developerId ? parseInt(developerId, 10) : 0;
  const [searchParams, setSearchParams] = useSearchParams();

  const eventsApi = useApi(`events:${id}`, signal => api.getSecurityEvents(id, signal));

  const events = eventsApi.data ?? [];
  const selectedParam = searchParams.get('event');
  const selectedId = selectedParam ? parseInt(selectedParam, 10) : events[0]?.id;

  const currentEvent = events.find(e => e.id === selectedId) || events[0];

  const historyApi = useApi(
    currentEvent ? `history:${currentEvent.id}` : null,
    signal => (currentEvent ? api.getLifecycleHistory(currentEvent.id, signal) : Promise.resolve([]))
  );

  const steps: TimelineStep[] = [];
  if (currentEvent) {
    const rawHistory = [...(historyApi.data ?? [])].sort(
      (a, b) => new Date(a.changedAt).getTime() - new Date(b.changedAt).getTime() || a.id - b.id
    );

    // Initial detection step if missing
    if (rawHistory.length === 0 || rawHistory[0].previousStatus !== null) {
      steps.push({
        key: 'initial-detected',
        status: 'DETECTED',
        previous: null,
        at: currentEvent.detectedAt,
        by: 'SYSTEM',
        fromEventRecord: true,
        sincePrevious: null,
      });
    }

    for (const h of rawHistory) {
      const prevStep = steps[steps.length - 1];
      const gapSeconds = prevStep
        ? Math.max(0, (new Date(h.changedAt).getTime() - new Date(prevStep.at).getTime()) / 1000)
        : null;

      steps.push({
        key: `history-${h.id}`,
        status: h.newStatus,
        previous: h.previousStatus,
        at: h.changedAt,
        by: h.changedBy,
        fromEventRecord: false,
        sincePrevious: gapSeconds,
      });
    }
  }

  if (eventsApi.error) {
    return <ErrorState error={eventsApi.error} onRetry={eventsApi.reload} />;
  }

  if (eventsApi.loading) {
    return <LoadingState />;
  }

  if (events.length === 0) {
    return (
      <EmptyState title="No security events yet">
        This developer has no security events, so there is no lifecycle history to display.
      </EmptyState>
    );
  }

  return (
    <>
      <PageHeader
        title="Vulnerability Lifecycle Timeline"
        description="How a security event moved through its lifecycle: DETECTED → OPENED → FIXED / IGNORED / REOPENED."
        endpoints={[
          `/api/security-events/developer/${id}`,
          `/api/lifecycle/security-event/${currentEvent?.id ?? '{securityEventId}'}`,
        ]}
      />

      <div className="card event-picker">
        <label htmlFor="event-select">Select Security Event</label>
        <select
          id="event-select"
          className="select select-wide"
          value={currentEvent?.id ?? ''}
          onChange={e => setSearchParams({ event: e.target.value })}
        >
          {events.map(e => (
            <option key={e.id} value={e.id}>
              #{e.id} · {e.vulnerabilityType} · {splitFilePath(e.fileName).name}:{e.lineNumber} ·{' '}
              {e.currentStatus}
            </option>
          ))}
        </select>
      </div>

      {currentEvent && (
        <div className="stack">
          <Card className="event-summary">
            <div className="event-summary-head">
              <h2 className="event-title mono">{currentEvent.vulnerabilityType}</h2>
              <SeverityBadge severity={currentEvent.severity} />
              <StatusBadge status={currentEvent.currentStatus} />
            </div>
            <p className="muted">{currentEvent.message}</p>
            <dl className="facts">
              <div>
                <dt>Security Event ID</dt>
                <dd className="mono">#{currentEvent.id}</dd>
              </div>
              <div>
                <dt>File and Line</dt>
                <dd className="mono break">
                  {currentEvent.fileName}:{currentEvent.lineNumber}
                </dd>
              </div>
              <div>
                <dt>Detected At</dt>
                <dd>
                  <time dateTime={currentEvent.detectedAt}>
                    {formatDateTime(currentEvent.detectedAt)}
                  </time>
                </dd>
              </div>
              <div>
                <dt>Lifecycle Status Changes</dt>
                <dd className="mono">{steps.length > 0 ? steps.length - 1 : 0}</dd>
              </div>
              <div>
                <dt>Latest Status</dt>
                <dd>
                  <StatusBadge status={currentEvent.currentStatus} />
                </dd>
              </div>
            </dl>
          </Card>

          <Card
            title="Lifecycle Audit Trail"
            description="Chronological status transitions recorded for this vulnerability from detection to current state."
          >
            {historyApi.loading ? (
              <LoadingState />
            ) : historyApi.error ? (
              <ErrorState error={historyApi.error} onRetry={historyApi.reload} />
            ) : (
              <>
                <div className="lifecycle-path">
                  <span className="visually-hidden">Lifecycle path: </span>
                  {steps.map((st, idx) => (
                    <React.Fragment key={st.key}>
                      {idx > 0 && <Icon name="arrowRight" size={14} className="path-arrow" />}
                      <StatusBadge status={st.status} />
                    </React.Fragment>
                  ))}
                </div>

                <ol className="timeline">
                  {steps.map(step => {
                    const conf = STATUS_CONFIG[step.status] ?? {
                      label: step.status,
                      tone: 'neutral',
                      icon: 'info',
                      description: '',
                    };
                    return (
                      <li key={step.key} className={`timeline-item tone-${conf.tone}`}>
                        <span className="timeline-node">
                          <Icon name={conf.icon} size={18} />
                        </span>
                        <div className="timeline-body">
                          <div className="timeline-heading">
                            <h3 className="timeline-status">{conf.label}</h3>
                            <span className="timeline-description">{conf.description}</span>
                            {step.sincePrevious !== null && (
                              <span className="timeline-gap">
                                <Icon name="clock" size={13} />
                                {formatDuration(step.sincePrevious)} after previous status
                              </span>
                            )}
                          </div>

                          <dl className="timeline-facts">
                            <div>
                              <dt>Previous Status</dt>
                              <dd>
                                {step.previous ? (
                                  <StatusBadge status={step.previous} />
                                ) : (
                                  <span className="muted">None (Initial event)</span>
                                )}
                              </dd>
                            </div>
                            <div>
                              <dt>New Status</dt>
                              <dd>
                                <StatusBadge status={step.status} />
                              </dd>
                            </div>
                            <div>
                              <dt>Changed Time</dt>
                              <dd>
                                <time dateTime={step.at}>{formatDateTime(step.at)}</time>
                              </dd>
                            </div>
                            <div>
                              <dt>Changed By</dt>
                              <dd className="mono">{step.by ?? 'SYSTEM'}</dd>
                            </div>
                          </dl>
                        </div>
                      </li>
                    );
                  })}
                </ol>
              </>
            )}
          </Card>
        </div>
      )}
    </>
  );
};
