import React from 'react';
import { BrowserRouter, Routes, Route, Link } from 'react-router';
import { Layout } from './components/Layout';
import { Home } from './pages/Home';
import { DeveloperProfile } from './pages/DeveloperProfile';
import { SecurityEvents } from './pages/SecurityEvents';
import { LifecycleTimeline } from './pages/LifecycleTimeline';
import { BehaviourAnalysis } from './pages/BehaviourAnalysis';
import { EmptyState } from './components/Cards';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Home />} />
          <Route path="developers/:developerId">
            <Route index element={<DeveloperProfile />} />
            <Route path="security-events" element={<SecurityEvents />} />
            <Route path="lifecycle" element={<LifecycleTimeline />} />
            <Route path="behaviour" element={<BehaviourAnalysis />} />
          </Route>
          <Route
            path="*"
            element={
              <EmptyState title="Page Not Found">
                This page does not exist. <Link to="/">Return to home</Link>.
              </EmptyState>
            }
          />
        </Route>
      </Routes>
    </BrowserRouter>
  );
};
