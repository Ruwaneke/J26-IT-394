import { useState } from "react";
import { Tabs, type TabDef } from "./components/Tabs";
import { DataBanner, ErrorState, Loading } from "./components/common";
import { useAnalytics } from "./data/useAnalytics";
import { useChartColors } from "./theme/useChartColors";
import { Overview } from "./pages/Overview";
import { Trends } from "./pages/Trends";
import { Forecast } from "./pages/Forecast";
import { Risk } from "./pages/Risk";
import { Correlations } from "./pages/Correlations";
import { Recommendations } from "./pages/Recommendations";
import { Evaluation } from "./pages/Evaluation";

const TABS: TabDef[] = [
  { id: "overview", label: "Overview" },
  { id: "trends", label: "Trends" },
  { id: "forecast", label: "Forecast" },
  { id: "risk", label: "Risk" },
  { id: "correlations", label: "Correlations" },
  { id: "recommendations", label: "Recommendations" },
  { id: "evaluation", label: "Model evaluation" },
];

export function App() {
  const { state, reload, inVsCode } = useAnalytics();
  const [tab, setTab] = useState("overview");
  const colors = useChartColors();

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>Sentinel Analytics</h1>
          <p className="muted small">
            Component 4 research dashboard
            {state.status === "ready" && <> · source: <code title={state.source}>{state.source}</code></>}
            {!inVsCode && <> · browser mode</>}
          </p>
        </div>
        <button className="button" onClick={reload} disabled={state.status === "loading"}>Reload data</button>
      </header>

      {state.status === "loading" && <Loading />}
      {state.status === "error" && <ErrorState message={state.message} onRetry={reload} />}
      {state.status === "ready" && (
        <>
          <DataBanner meta={state.data.meta} />
          {state.warning && <div className="warning" role="alert">{state.warning}</div>}
          <Tabs tabs={TABS} selected={tab} onSelect={setTab} />
          <main id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`} className="panel" tabIndex={0}>
            {tab === "overview" && <Overview data={state.data} colors={colors} />}
            {tab === "trends" && <Trends data={state.data} colors={colors} />}
            {tab === "forecast" && <Forecast data={state.data} colors={colors} />}
            {tab === "risk" && <Risk data={state.data} />}
            {tab === "correlations" && <Correlations data={state.data} colors={colors} />}
            {tab === "recommendations" && <Recommendations data={state.data} />}
            {tab === "evaluation" && <Evaluation data={state.data} colors={colors} />}
          </main>
        </>
      )}
    </div>
  );
}
