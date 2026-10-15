import React from 'react';
import { useParams, Link } from 'react-router';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import {
  PageHeader,
  Card,
  StatTile,
  LoadingState,
  ErrorState,
  EmptyState,
  formatDate,
  formatDateTime,
  formatDuration,
  formatNumber,
} from '../components/Cards';
import { ActionBadge, ClassificationBadge, getClassificationInfo } from '../components/Badges';
import { Icon } from '../components/Icon';
import { Developer } from '../types';

export const DeveloperProfile: React.FC = () => {
  const { developerId } = useParams<{ developerId: string }>();
  const id = developerId ? parseInt(developerId, 10) : 0;

  const devApi = useApi(`developer:${id}`, signal => api.getDeveloper(id, signal));
  const summaryApi = useApi(`summary:${id}`, signal => api.getBehaviourSummary(id, signal));
  const interactionsApi = useApi(`interactions:${id}`, signal => api.getInteractions(id, signal));

  if (devApi.error) {
    return <ErrorState error={devApi.error} onRetry={devApi.reload} />;
  }

  if (devApi.loading || !devApi.data) {
    return <LoadingState />;
  }

  const dev: Developer = devApi.data;
  const avatarLetter = dev.developerIdentifier.slice(0, 2).toUpperCase() || '?';
  const hasGitHub = !!(dev.githubUsername || dev.githubId);

  const interactions = interactionsApi.data ?? [];
  const recentActions = [...interactions]
    .sort((a, b) => new Date(b.actionTimestamp).getTime() - new Date(a.actionTimestamp).getTime())
    .slice(0, 8);

  const classification = summaryApi.data?.behaviourClassification;
  const classInfo = classification ? getClassificationInfo(classification) : null;

  return (
    <>
      <PageHeader
        title="Developer Profile"
        description="Who the tracked developer is, their security events summary, and how they respond to security vulnerabilities."
        endpoints={[
          `/api/developers/${id}`,
          `/api/developer-behaviour/${id}`,
          `/api/developer-interactions/developer/${id}`,
        ]}
      />

      <div className="stack">
        <Card className="identity">
          <div className="identity-main">
            <div className="avatar" aria-hidden="true">
              {avatarLetter}
            </div>
            <div>
              <p className="eyebrow">Developer #{dev.id}</p>
              <h2 className="identity-name">{dev.developerIdentifier}</h2>
              <p className="muted">Tracked since {formatDate(dev.createdAt)}</p>
            </div>
          </div>

          <dl className="facts">
            <div>
              <dt>Developer ID</dt>
              <dd className="mono">{dev.id}</dd>
            </div>
            <div>
              <dt>Developer Identifier</dt>
              <dd className="mono">{dev.developerIdentifier}</dd>
            </div>
            <div>
              <dt>GitHub Identity</dt>
              <dd>
                {dev.githubUsername ? (
                  <a
                    href={`https://github.com/${encodeURIComponent(dev.githubUsername)}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    @{dev.githubUsername} <Icon name="external" size={13} />
                  </a>
                ) : hasGitHub ? (
                  <span>Linked</span>
                ) : (
                  <span className="muted">Not linked – local developer</span>
                )}
              </dd>
            </div>
            {dev.githubId && (
              <div>
                <dt>GitHub User ID</dt>
                <dd className="mono">{dev.githubId}</dd>
              </div>
            )}
            {dev.email && (
              <div>
                <dt>Email</dt>
                <dd>{dev.email}</dd>
              </div>
            )}
          </dl>
        </Card>

        <div className="grid grid-tiles">
          <StatTile
            label="Total Security Events"
            icon="alert"
            value={summaryApi.data ? formatNumber(summaryApi.data.totalSecurityEvents) : '—'}
            detail="Vulnerabilities detected in this developer’s code"
          />

          <div className="card stat-tile">
            <div className="stat-label">
              <Icon name="shield" size={15} />
              Behaviour Classification
            </div>
            {summaryApi.loading ? (
              <LoadingState />
            ) : summaryApi.error ? (
              <p className="muted">Could not load classification</p>
            ) : classification && classInfo ? (
              <div className="classification-tile">
                <ClassificationBadge code={classification} />
                <p className="stat-detail">{classInfo.summary}</p>
                <Link to={`/developers/${id}/behaviour`} className="row-link">
                  See full behaviour analysis <Icon name="arrowRight" size={14} />
                </Link>
              </div>
            ) : (
              <p className="muted">No classification available</p>
            )}
          </div>
        </div>

        <Card
          title="Recent Developer Actions"
          description="The latest responses to security events recorded from the IDE, newest first."
        >
          {interactionsApi.loading ? (
            <LoadingState />
          ) : interactionsApi.error ? (
            <ErrorState error={interactionsApi.error} onRetry={interactionsApi.reload} />
          ) : recentActions.length === 0 ? (
            <EmptyState title="No actions recorded yet">
              Actions appear here when the developer opens, fixes, ignores, or reopens a security event.
            </EmptyState>
          ) : (
            <>
              <ol className="activity-list">
                {recentActions.map(action => (
                  <li key={action.id} className="activity-item">
                    <ActionBadge action={action.action} />
                    <div className="activity-main">
                      {action.securityEventId ? (
                        <Link to={`/developers/${id}/lifecycle?event=${action.securityEventId}`}>
                          Security event #{action.securityEventId}
                        </Link>
                      ) : (
                        <span>General security interaction</span>
                      )}
                      <span className="activity-meta">
                        {action.timeSinceDetectionSeconds !== null && (
                          <>Responded {formatDuration(action.timeSinceDetectionSeconds)} after detection</>
                        )}
                        {action.source && ` · via ${action.source}`}
                      </span>
                    </div>
                    <time className="activity-time" dateTime={action.actionTimestamp}>
                      {formatDateTime(action.actionTimestamp)}
                    </time>
                  </li>
                ))}
              </ol>
              {interactions.length > recentActions.length && (
                <p className="card-foot">
                  Showing the latest {recentActions.length} of {formatNumber(interactions.length)} actions.
                </p>
              )}
            </>
          )}
        </Card>
      </div>
    </>
  );
};
