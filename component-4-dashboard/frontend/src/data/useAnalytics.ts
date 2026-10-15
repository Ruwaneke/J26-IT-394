import { useCallback, useEffect, useRef, useState } from "react";
import type { Analytics } from "../types/analytics";
import { parseAnalytics } from "./parse";

// Messages exchanged with the extension (see extension/src/extension.ts).
export type HostToWebview =
  | { type: "data"; payload: unknown; source: string; warning?: string }
  | { type: "error"; message: string };
export type WebviewToHost = { type: "ready" } | { type: "reload" };

type VsCodeApi = { postMessage(message: WebviewToHost): void };
declare global {
  function acquireVsCodeApi(): VsCodeApi;
}

let vscodeApi: VsCodeApi | null | undefined;
function getVsCodeApi(): VsCodeApi | null {
  if (vscodeApi === undefined) {
    vscodeApi = typeof acquireVsCodeApi === "function" ? acquireVsCodeApi() : null;
  }
  return vscodeApi;
}

export type LoadState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; data: Analytics; source: string; warning?: string };

/**
 * Standalone browser mode: load the bundled sample, or ?data=<relative path>
 * on the same origin (e.g. a local copy of the full analytics.json).
 */
function browserDataUrl(): URL {
  const param = new URLSearchParams(window.location.search).get("data");
  const url = new URL(param ?? "sample-analytics.json", window.location.href);
  if (url.origin !== window.location.origin) throw new Error("?data= must point to a file on the same origin.");
  return url;
}

export function useAnalytics(): { state: LoadState; reload: () => void; inVsCode: boolean } {
  const [state, setState] = useState<LoadState>({ status: "loading" });
  const api = useRef(getVsCodeApi());

  const accept = useCallback((payload: unknown, source: string, warning?: string) => {
    try {
      setState({ status: "ready", data: parseAnalytics(payload), source, warning });
    } catch (e) {
      setState({ status: "error", message: e instanceof Error ? e.message : String(e) });
    }
  }, []);

  const loadInBrowser = useCallback(async () => {
    setState({ status: "loading" });
    try {
      const url = browserDataUrl();
      const res = await fetch(url, { cache: "no-store" });
      if (!res.ok) throw new Error(`Could not load ${url.pathname} (HTTP ${res.status}).`);
      accept(await res.json(), url.pathname);
    } catch (e) {
      setState({ status: "error", message: e instanceof Error ? e.message : String(e) });
    }
  }, [accept]);

  useEffect(() => {
    const host = api.current;
    if (!host) {
      void loadInBrowser();
      return;
    }
    const onMessage = (event: MessageEvent<HostToWebview>) => {
      const msg = event.data;
      if (!msg || typeof msg !== "object") return;
      if (msg.type === "data") accept(msg.payload, msg.source, msg.warning);
      else if (msg.type === "error") setState({ status: "error", message: msg.message });
    };
    window.addEventListener("message", onMessage);
    host.postMessage({ type: "ready" });
    return () => window.removeEventListener("message", onMessage);
  }, [accept, loadInBrowser]);

  const reload = useCallback(() => {
    if (api.current) {
      setState({ status: "loading" });
      api.current.postMessage({ type: "reload" });
    } else {
      void loadInBrowser();
    }
  }, [loadInBrowser]);

  return { state, reload, inVsCode: api.current !== null };
}
