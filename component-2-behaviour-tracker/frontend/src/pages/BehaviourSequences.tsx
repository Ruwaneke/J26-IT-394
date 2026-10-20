import React from 'react';
import { useApi } from '../hooks/useApi';
import { api } from '../api/client';
import {
  Card,
  StatTile,
  LoadingState,
  ErrorState,
  EmptyState,
  formatDateTime,
  formatNumber,
  formatPercent,
} from '../components/Cards';
import { ActionBadge } from '../components/Badges';
import { Icon } from '../components/Icon';
import { BehaviourAction, ResponseSequenceAnalysis } from '../types';
import './BehaviourSequences.css';

/**
 * Behaviour Sequence Intelligence (TASKS P2-10): the order of a developer's actions on each
 * security event, and the response patterns that recur across events. Every value shown
 * comes from GET /api/developer-behaviour/{id}/response-sequences; nothing is illustrative.
 */
export const BehaviourSequenceIntelligence: React.FC<{ developerId: number }> = ({ developerId }) => {
  const sequencesApi = useApi(`sequences:${developerId}`, signal =>
    api.getResponseSequences(developerId, signal)
  );

  return (
    <>
      <h2 className="section-title">Behaviour Sequence Intelligence</h2>
      <p className="muted sequence-intro">
        The order in which this developer responded to each security event, from recorded developer
        actions only (detection by the system is not an action). Counts describe what was recorded;
        they are not causes or predictions.
      </p>

      {sequencesApi.error ? (
        <ErrorState error={sequencesApi.error} onRetry={sequencesApi.reload} />
      ) : sequencesApi.loading || !sequencesApi.data ? (
        <LoadingState />
      ) : (
        <SequenceResults data={sequencesApi.data} />
      )}
    </>
  );
};

const SequenceResults: React.FC<{ data: ResponseSequenceAnalysis }> = ({ data }) => {
  const { thresholds, dominantPattern: dominant } = data;
  const insufficient = data.analysisStatus === 'INSUFFICIENT_DATA';

  return (
    <div className="stack">
      <div className="grid grid-tiles">
        <StatTile
          label="Complete Response Sequences"
          icon="timeline"
          value={formatNumber(data.totalEligibleSequences)}
          detail={
            data.excludedIncompleteEvents > 0
              ? `${formatNumber(data.totalEligibleEvents)} events with actions; ${formatNumber(
                  data.excludedIncompleteEvents
                )} left out (action without a timestamp)`
              : `One per security event with recorded actions; at least ${thresholds.minSequences} needed`
          }
        />
        <StatTile
          label="Developer Actions Used"
          icon="activity"
          value={formatNumber(data.totalActionRecords - data.excludedActionRecords)}
          detail={
            data.excludedActionRecords > 0
              ? `${formatNumber(data.excludedActionRecords)} of ${formatNumber(
                  data.totalActionRecords
                )} not tied to this developer's own events`
              : `All ${formatNumber(data.totalActionRecords)} recorded actions`
          }
        />
        <StatTile
          label="Repeats Merged"
          icon="repeat"
          value={formatNumber(data.collapsedRepeatActions)}
          detail="The same action again on the same event (e.g. a second OPEN) counts as one step"
        />
      </div>

      {insufficient ? (
        <EmptyState title="Insufficient data for sequence analysis">
          {data.insufficientDataReason}. No patterns or transitions are reported until there is
          enough evidence.
        </EmptyState>
      ) : (
        <>
          <Card
            title="Dominant Response Pattern"
            description="The most frequent complete sequence of actions on one security event."
          >
            {dominant.status === 'FOUND' && dominant.actions ? (
              <div className="dominant-pattern">
                <ActionChain actions={dominant.actions} />
                <p className="muted">
                  Seen on {formatNumber(dominant.occurrenceCount)} of{' '}
                  {formatNumber(dominant.eligibleSequenceCount)} complete sequences (
                  {formatPercent(dominant.supportPercent)} support). Last seen{' '}
                  {formatDateTime(dominant.lastOccurredAt)}.
                </p>
              </div>
            ) : (
              <EmptyState title="No dominant pattern (INSUFFICIENT_DATA)">{dominant.reason}.</EmptyState>
            )}
          </Card>

          <Card
            title="Most Frequent Response Sequences"
            description={`Contiguous patterns of 2 to 5 actions found in at least ${thresholds.minPatternSequences} sequences and ${thresholds.minSupportPercent}% of them. Support = sequences containing the pattern ÷ ${formatNumber(data.totalEligibleSequences)} complete sequences.`}
          >
            {data.frequentPatterns.length === 0 ? (
              <EmptyState title="No pattern reaches the evidence threshold">
                Recorded sequences do not repeat often enough to report a pattern.
              </EmptyState>
            ) : (
              <div className="table-wrap">
                <table className="data-table compact">
                  <thead>
                    <tr>
                      <th scope="col">Sequence</th>
                      <th scope="col" className="num">
                        Sequences
                      </th>
                      <th scope="col" className="num">
                        Occurrences
                      </th>
                      <th scope="col">Support</th>
                      <th scope="col">Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.frequentPatterns.map(pattern => (
                      <tr key={pattern.actions.join('>')}>
                        <td>
                          <ActionChain actions={pattern.actions} />
                        </td>
                        <td className="num">
                          {formatNumber(pattern.sequenceCount)} / {formatNumber(pattern.eligibleSequenceCount)}
                        </td>
                        <td className="num">{formatNumber(pattern.occurrenceCount)}</td>
                        <td>
                          <ShareBar value={pattern.supportPercent} label="Support" />
                        </td>
                        <td className="nowrap">{formatDateTime(pattern.lastOccurredAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card
            title="Action Transition Probabilities"
            description={`Share of each action's next actions on the same event (count ÷ that action's outgoing transitions). Samples under ${thresholds.minTransitionSample} are marked as small.`}
          >
            {data.transitionAnalysis.length === 0 ? (
              <EmptyState title="No transitions recorded">
                Every complete sequence has a single action, so no action is followed by another.
              </EmptyState>
            ) : (
              <div className="table-wrap">
                <table className="data-table compact">
                  <thead>
                    <tr>
                      <th scope="col">Transition</th>
                      <th scope="col" className="num">
                        Count
                      </th>
                      <th scope="col" className="num">
                        Sample size
                      </th>
                      <th scope="col">Probability</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.transitionAnalysis.map(t => (
                      <tr key={`${t.fromAction}>${t.toAction}`}>
                        <td>
                          <ActionChain actions={[t.fromAction, t.toAction]} />
                        </td>
                        <td className="num">{formatNumber(t.transitionCount)}</td>
                        <td className="num">
                          {formatNumber(t.outgoingSampleSize)}
                          {!t.sufficientSample && <span className="sample-flag">small sample</span>}
                        </td>
                        <td>
                          <ShareBar value={t.probabilityPercent} label="Probability" />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}

      <p className="muted sequence-note">
        <Icon name="info" size={13} />
        <span>
          Repeated actions on one event are merged; actions on different events never form one
          sequence. A FIX is the developer's claimed fix. Thresholds: at least {thresholds.minSequences}{' '}
          complete sequences, {thresholds.minPatternSequences} sequences and{' '}
          {thresholds.minSupportPercent}% support per pattern.
        </span>
      </p>
    </div>
  );
};

const ActionChain: React.FC<{ actions: BehaviourAction[] }> = ({ actions }) => (
  <span className="sequence-chain">
    <span className="visually-hidden">Sequence: {actions.join(' then ')}</span>
    {actions.map((action, idx) => (
      <React.Fragment key={idx}>
        {idx > 0 && <Icon name="arrowRight" size={13} className="path-arrow" />}
        <ActionBadge action={action} />
      </React.Fragment>
    ))}
  </span>
);

const ShareBar: React.FC<{ value: number; label: string }> = ({ value, label }) => (
  <span className="share-bar">
    <span
      className="meter-track"
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value}
      aria-valuetext={formatPercent(value)}
    >
      {value > 0 && <span className="meter-fill" style={{ width: `${Math.min(100, value)}%` }} />}
    </span>
    <span className="share-value">{formatPercent(value)}</span>
  </span>
);
