import React, { useState, useId } from 'react';
import { NavLink, Outlet, useNavigate, useLocation, useParams, Link } from 'react-router';
import { Icon } from './Icon';
import { useTheme } from '../hooks/useTheme';

export const Layout: React.FC = () => {
  const { developerId } = useParams<{ developerId?: string }>();
  const [theme, toggleTheme] = useTheme();
  const navigate = useNavigate();
  const location = useLocation();

  const [devInput, setDevInput] = useState(developerId || '');
  const [inputError, setInputError] = useState(false);
  const inputId = useId();

  // Keep input in sync with route param
  React.useEffect(() => {
    if (developerId) {
      setDevInput(developerId);
      setInputError(false);
    }
  }, [developerId]);

  const handleSelectDeveloper = (e: React.FormEvent) => {
    e.preventDefault();
    const parsed = parseInt(devInput.trim(), 10);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
      setInputError(true);
      return;
    }
    setInputError(false);

    // Keep current sub-tab if already on a developer page
    const subPathMatch = /^\/developers\/[^/]+(\/(?:security-events|lifecycle|behaviour))?/.exec(
      location.pathname
    );
    const subPath = subPathMatch?.[1] ?? '';
    navigate(`/developers/${parsed}${subPath}`);
  };

  const currentDev = developerId ? parseInt(developerId, 10) : null;

  return (
    <div className="app">
      <a href="#main-content" className="skip-link">
        Skip to content
      </a>

      <aside className="sidebar">
        <Link to="/" className="brand">
          <span className="brand-mark">
            <Icon name="shield" size={20} />
          </span>
          <div>
            <span className="brand-title">Sentinel</span>
            <span className="brand-subtitle">Behaviour Tracker</span>
          </div>
        </Link>

        <nav className="nav" aria-label="Main navigation">
          {currentDev ? (
            <>
              <NavLink
                to={`/developers/${currentDev}`}
                end
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              >
                <Icon name="user" size={16} />
                <span>Developer Profile</span>
              </NavLink>

              <NavLink
                to={`/developers/${currentDev}/security-events`}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              >
                <Icon name="list" size={16} />
                <span>Security Events</span>
              </NavLink>

              <NavLink
                to={`/developers/${currentDev}/lifecycle`}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              >
                <Icon name="timeline" size={16} />
                <span>Lifecycle Timeline</span>
              </NavLink>

              <NavLink
                to={`/developers/${currentDev}/behaviour`}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
              >
                <Icon name="activity" size={16} />
                <span>Behaviour Analysis</span>
              </NavLink>
            </>
          ) : (
            <>
              <span className="nav-link is-disabled" title="Select a developer first">
                <Icon name="user" size={16} />
                <span>Developer Profile</span>
              </span>
              <span className="nav-link is-disabled" title="Select a developer first">
                <Icon name="list" size={16} />
                <span>Security Events</span>
              </span>
              <span className="nav-link is-disabled" title="Select a developer first">
                <Icon name="timeline" size={16} />
                <span>Lifecycle Timeline</span>
              </span>
              <span className="nav-link is-disabled" title="Select a developer first">
                <Icon name="activity" size={16} />
                <span>Behaviour Analysis</span>
              </span>
            </>
          )}
        </nav>

        <p className="sidebar-note">
          Final Year Research Project
          <br />
          Component 2 Demonstration
        </p>
      </aside>

      <div className="main">
        <header className="topbar">
          <form className="developer-selector" onSubmit={handleSelectDeveloper} noValidate>
            <label htmlFor={inputId}>Developer ID</label>
            <input
              id={inputId}
              type="text"
              className="input"
              value={devInput}
              onChange={e => {
                setDevInput(e.target.value);
                if (inputError) setInputError(false);
              }}
              placeholder="e.g. 1"
              aria-invalid={inputError}
            />
            <button type="submit" className="button">
              Go
            </button>
            {inputError && (
              <div className="field-error" role="alert">
                <Icon name="error" size={14} />
                <span>Enter a valid ID number</span>
              </div>
            )}
          </form>

          <button
            type="button"
            className="icon-button"
            onClick={toggleTheme}
            title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
            aria-label="Toggle theme"
          >
            <Icon name={theme === 'light' ? 'moon' : 'sun'} size={16} />
          </button>
        </header>

        <main id="main-content" className="content" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
};
