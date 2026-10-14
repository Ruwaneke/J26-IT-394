import React from 'react';
import { Icon } from './Icon';
import {
  ClassificationRule,
  SecurityEventStatus,
  Severity,
  BehaviourAction,
} from '../types';

export const CLASSIFICATION_RULES: ClassificationRule[] = [
  {
    code: 'INSUFFICIENT_DATA',
    label: 'Insufficient data',
    tone: 'neutral',
    icon: 'help',
    summary: 'Not enough activity has been recorded to classify this developer yet.',
    rule: 'Fewer than 3 security events or fewer than 3 recorded actions',
  },
  {
    code: 'SECURITY_RESPONSIVE',
    label: 'Security responsive',
    tone: 'good',
    icon: 'shieldCheck',
    summary: 'Fixes most security events, including high-severity ones, and rarely ignores them.',
    rule: 'Fix rate ≥ 80%, high-severity fix rate ≥ 80% (or no high-severity events) and ignore rate < 20%',
  },
  {
    code: 'SECURITY_AT_RISK',
    label: 'Security at risk',
    tone: 'critical',
    icon: 'shieldAlert',
    summary: 'Often ignores security events or leaves high-severity vulnerabilities unfixed.',
    rule: 'Ignore rate ≥ 40% or high-severity fix rate < 50%',
  },
  {
    code: 'RECURRING_SECURITY_BEHAVIOUR',
    label: 'Recurring security behaviour',
    tone: 'warning',
    icon: 'repeat',
    summary: 'Vulnerabilities keep coming back, or the same vulnerability types keep recurring.',
    rule: 'Reopen rate ≥ 30% or 3 or more repeated vulnerability types',
  },
  {
    code: 'SECURITY_NEUTRAL',
    label: 'Security neutral',
    tone: 'info',
    icon: 'shield',
    summary: 'Mixed behaviour with no strong positive or negative pattern.',
    rule: 'None of the rules above apply',
  },
];

export function getClassificationInfo(code: string): ClassificationRule {
  return (
    CLASSIFICATION_RULES.find(r => r.code === code) ?? {
      code,
      label: code,
      tone: 'neutral',
      icon: 'help',
      summary: 'Classification returned by the backend.',
      rule: '',
    }
  );
}

export const STATUS_CONFIG: Record<
  SecurityEventStatus,
  { label: string; tone: string; icon: string; description: string }
> = {
  DETECTED: {
    label: 'Detected',
    tone: 'warning',
    icon: 'alert',
    description: 'Found in the code; no developer action yet',
  },
  OPENED: {
    label: 'Opened',
    tone: 'info',
    icon: 'eye',
    description: 'The developer opened the explanation',
  },
  FIXED: {
    label: 'Fixed',
    tone: 'good',
    icon: 'check',
    description: 'The developer fixed the vulnerability',
  },
  IGNORED: {
    label: 'Ignored',
    tone: 'neutral',
    icon: 'eyeOff',
    description: 'Ignored or dismissed without a fix',
  },
  REOPENED: {
    label: 'Reopened',
    tone: 'critical',
    icon: 'reopen',
    description: 'A fixed or ignored vulnerability became active again',
  },
};

export const SEVERITY_CONFIG: Record<
  Severity,
  { label: string; tone: string; level: number }
> = {
  LOW: { label: 'Low', tone: 'neutral', level: 1 },
  MEDIUM: { label: 'Medium', tone: 'warning', level: 2 },
  HIGH: { label: 'High', tone: 'serious', level: 3 },
  CRITICAL: { label: 'Critical', tone: 'critical', level: 4 },
};

export const ACTION_CONFIG: Record<
  BehaviourAction,
  { label: string; tone: string; icon: string; description: string }
> = {
  OPEN: {
    label: 'Opened',
    tone: 'info',
    icon: 'eye',
    description: 'Opened the explanation of the vulnerability',
  },
  FIX: {
    label: 'Fixed',
    tone: 'good',
    icon: 'check',
    description: 'Fixed the vulnerability',
  },
  IGNORE: {
    label: 'Ignored',
    tone: 'neutral',
    icon: 'eyeOff',
    description: 'Ignored the warning',
  },
  DISMISS: {
    label: 'Dismissed',
    tone: 'neutral',
    icon: 'dismiss',
    description: 'Dismissed the warning',
  },
  REOPEN: {
    label: 'Reopened',
    tone: 'critical',
    icon: 'reopen',
    description: 'Reopened a closed vulnerability',
  },
};

export const Badge: React.FC<{
  tone: string;
  icon?: string;
  label: string;
  title?: string;
}> = ({ tone, icon, label, title }) => (
  <span className={`badge tone-${tone}`} title={title}>
    {icon && <Icon name={icon} size={14} className="badge-icon" />}
    {label}
  </span>
);

export const StatusBadge: React.FC<{ status: SecurityEventStatus }> = ({ status }) => {
  const conf = STATUS_CONFIG[status] ?? {
    label: status,
    tone: 'neutral',
    icon: 'info',
    description: status,
  };
  return <Badge tone={conf.tone} icon={conf.icon} label={conf.label} title={conf.description} />;
};

export const ActionBadge: React.FC<{ action: BehaviourAction }> = ({ action }) => {
  const conf = ACTION_CONFIG[action] ?? {
    label: action,
    tone: 'neutral',
    icon: 'info',
    description: action,
  };
  return <Badge tone={conf.tone} icon={conf.icon} label={conf.label} title={conf.description} />;
};

export const ClassificationBadge: React.FC<{ code: string }> = ({ code }) => {
  const conf = getClassificationInfo(code);
  return <Badge tone={conf.tone} icon={conf.icon} label={conf.label} title={conf.code} />;
};

export const SeverityBadge: React.FC<{ severity: Severity }> = ({ severity }) => {
  const conf = SEVERITY_CONFIG[severity] ?? { label: severity, tone: 'neutral', level: 0 };
  return (
    <span className={`badge tone-${conf.tone}`} title={`${conf.label} severity`}>
      <span className="severity-bars" aria-hidden="true">
        {[1, 2, 3, 4].map(level => (
          <span key={level} className={level <= conf.level ? 'is-filled' : undefined} />
        ))}
      </span>
      {conf.label}
    </span>
  );
};
