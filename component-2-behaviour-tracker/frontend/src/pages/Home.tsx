import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { PageHeader, Card, LoadingState } from '../components/Cards';
import { Icon } from '../components/Icon';
import { api } from '../api/client';
import { Developer } from '../types';

export const Home: React.FC = () => {
  const [developers, setDevelopers] = useState<Developer[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    api
      .getAllDevelopers()
      .then(devs => setDevelopers(devs))
      .catch(() => setDevelopers([]))
      .finally(() => setLoading(false));
  }, []);

  const features = [
    {
      icon: 'user',
      title: 'Developer Profile',
      text: 'Identity, GitHub link, total security events, and real-time behaviour classification badge.',
    },
    {
      icon: 'list',
      title: 'Security Events',
      text: 'Every vulnerability detected in the developer’s code, with severity, file, line number, and current status.',
    },
    {
      icon: 'timeline',
      title: 'Lifecycle Timeline',
      text: 'How security events transition through DETECTED → OPENED → FIXED / IGNORED / REOPENED.',
    },
    {
      icon: 'activity',
      title: 'Behaviour Analysis',
      text: 'Fix rate, ignore rate, reopen rate, high-severity fix rate, average response time, and repeated count.',
    },
  ];

  return (
    <>
      <PageHeader
        title="Developer Behaviour Dashboard"
        description="Research demonstration of Component 2 – Intelligent Developer Behaviour Tracking Module. It tracks real-time security events detected by Sentinel in VS Code and monitors developer response patterns."
      />

      <Card
        title="Choose a Developer"
        description="Select a registered developer or enter an ID in the top navigation bar to inspect their security behaviour."
      >
        <div className="home-body">
          {loading ? (
            <LoadingState />
          ) : developers.length > 0 ? (
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '16px' }}>
              {developers.map(dev => (
                <button
                  key={dev.id}
                  type="button"
                  className="button button-primary"
                  onClick={() => navigate(`/developers/${dev.id}`)}
                >
                  <Icon name="user" size={14} />
                  <span>
                    Developer #{dev.id} ({dev.developerIdentifier})
                  </span>
                  <Icon name="arrowRight" size={14} />
                </button>
              ))}
            </div>
          ) : (
            <p className="muted" style={{ marginBottom: '16px' }}>
              No developers registered yet. Enter ID 1 or authenticate via the VS Code extension.
            </p>
          )}

          <ul className="page-list">
            {features.map(f => (
              <li key={f.title}>
                <Icon name={f.icon} size={18} />
                <div>
                  <strong>{f.title}</strong>
                  <span>{f.text}</span>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </Card>
    </>
  );
};
