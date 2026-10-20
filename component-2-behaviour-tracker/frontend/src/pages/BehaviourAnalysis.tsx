import React from 'react';
import { useParams } from 'react-router';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import {
  PageHeader,
  Card,
  StatTile,
  Meter,
  LoadingState,
  ErrorState,
  formatDuration,
  formatNumber,
} from '../components/Cards';
import {
  ClassificationBadge,
  ActionBadge,
  CLASSIFICATION_RULES,
  getClassificationInfo,
} from '../components/Badges';
import { Icon } from '../components/Icon';
import { BehaviourSequenceIntelligence } from './BehaviourSequences';
import { DeveloperBehaviourSummary, BehaviourAction } from '../types';

export const BehaviourAnalysis: React.FC = () => {
  const { developerId } = useParams<{ developerId: string }>();
  const id = developerId ? parseInt(developerId, 10) : 0;

  const summaryApi = useApi(`behaviour:${id}`, signal => api.getBehaviourSummary(id, signal));

  if (summaryApi.error) {
    return <ErrorState error={summaryApi.error} onRetry={summaryApi.reload} />;
  }

  if (summaryApi.loading || !summaryApi.data) {
    return <LoadingState />;
  }

  const summary: DeveloperBehaviourSummary = summaryApi.data;
  const classification = getClassificationInfo(summary.behaviourClassification);
  const totalEvents = summary.totalSecurityEvents;

  const actionsList: [BehaviourAction, number][] = [
    ['OPEN', summary.openedCount],
    ['FIX', summary.fixedCount],
    ['IGNORE', summary.ignoredCount],
    ['DISMISS', summary.dismissedCount],
    ['REOPEN', summary.reopenedCount],
  ];

  const hasRecordedActions = actionsList.some(([, count]) => count > 0);

  return (
    <>
      <PageHeader
        title="Developer Behaviour Analysis"
        description="Fix, ignore, and reopen metrics derived from developer reactions in VS Code, and the explainable classification evaluated by the backend."
        endpoints={[`/api/developer-behaviour/${id}`, `/api/developer-behaviour/${id}/response-sequences`]}
      />

      <div className="stack">
        <section
          className={`hero tone-${classification.tone}`}
          aria-labelledby="classification-heading"
        >
          <span className="hero-icon">
            <Icon name={classification.icon} size={30} />
          </span>
          <div>
            <p className="eyebrow">Final Behaviour Classification</p>
            <h2 id="classification-heading" className="hero-label">
              {classification.label}
            </h2>
            <p className="hero-code mono">{classification.code}</p>
            <p className="hero-summary">{classification.summary}</p>
          </div>
        </section>

        <h2 className="section-title">Response Rates & Metrics</h2>

        <div className="grid grid-meters">
          <Meter
            label="Fix Rate"
            value={summary.fixRate}
            higherIsBetter={true}
            detail={`${formatNumber(summary.fixedCount)} of ${formatNumber(totalEvents)} vulnerabilities fixed`}
          />
          <Meter
            label="Ignore Rate"
            value={summary.ignoreRate}
            higherIsBetter={false}
            detail="Vulnerabilities explicitly ignored or dismissed"
          />
          <Meter
            label="Reopen Rate"
            value={summary.reopenRate}
            higherIsBetter={false}
            detail={`${formatNumber(summary.reopenedCount)} of ${formatNumber(totalEvents)} vulnerabilities reopened`}
          />
          <Meter
            label="High Severity Fix Rate"
            value={summary.highSeverityFixRate}
            higherIsBetter={true}
            detail={
              summary.highSeverityFixRate === null
                ? 'Not applicable: no HIGH or CRITICAL security events'
                : 'HIGH and CRITICAL vulnerabilities resolved'
            }
          />
        </div>

        <div className="grid grid-tiles">
          <StatTile
            label="Average Response Time"
            icon="clock"
            value={
              hasRecordedActions ? formatDuration(summary.averageResponseTimeSeconds) : '—'
            }
            detail={
              hasRecordedActions
                ? 'Mean time from detection to developer action'
                : 'No developer actions recorded yet'
            }
          />
          <StatTile
            label="Repeated Vulnerability Count"
            icon="repeat"
            value={formatNumber(summary.repeatedVulnerabilityCount)}
            detail="Vulnerability categories recurring more than once"
          />
          <StatTile
            label="Total Security Events"
            icon="alert"
            value={formatNumber(totalEvents)}
            detail="Denominator for all rate calculations"
          />
        </div>

        <div className="grid grid-split">
          <Card
            title="Classification Decision Rules"
            description="The intelligent behaviour tracking engine checks these rules in top-to-bottom priority order."
          >
            <ol className="rules">
              {CLASSIFICATION_RULES.map(rule => {
                const isMatch = rule.code === summary.behaviourClassification;
                return (
                  <li
                    key={rule.code}
                    className={`rule tone-${rule.tone} ${isMatch ? 'is-match' : ''}`}
                    aria-current={isMatch ? 'true' : undefined}
                  >
                    <ClassificationBadge code={rule.code} />
                    <span className="rule-text">{rule.rule}</span>
                    {isMatch && <span className="rule-match">Current Match</span>}
                  </li>
                );
              })}
            </ol>
          </Card>

          <Card
            title="Action Counts"
            description="Breakdown of developer interactions recorded across all security events."
          >
            <table className="data-table compact">
              <thead>
                <tr>
                  <th scope="col">Action</th>
                  <th scope="col" className="num">
                    Events
                  </th>
                </tr>
              </thead>
              <tbody>
                {actionsList.map(([action, count]) => (
                  <tr key={action}>
                    <td>
                      <ActionBadge action={action} />
                    </td>
                    <td className="num">{formatNumber(count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </div>

        <BehaviourSequenceIntelligence developerId={id} />
      </div>
    </>
  );
};
