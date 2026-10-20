import axios, { AxiosError } from 'axios';
import {
  Developer,
  SecurityEvent,
  DeveloperInteraction,
  LifecycleHistory,
  DeveloperBehaviourSummary,
  ResponseSequenceAnalysis,
  QualityStatus,
  TestRunState,
} from '../types';

export class ApiError extends Error {
  status?: number;
  unreachable: boolean;

  constructor(message: string, status?: number, unreachable = false) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.unreachable = unreachable;
  }
}

const apiClient = axios.create({
  baseURL: '/api',
  timeout: 10000,
  headers: {
    Accept: 'application/json',
  },
});

function isErrorResponse(data: unknown): data is { message: string; status: number } {
  return (
    typeof data === 'object' &&
    data !== null &&
    'message' in data &&
    typeof (data as { message: unknown }).message === 'string'
  );
}

export function normalizeError(err: unknown): ApiError {
  if (err instanceof ApiError) {
    return err;
  }
  if (axios.isAxiosError(err)) {
    const res = err.response;
    if (res && isErrorResponse(res.data)) {
      return new ApiError(res.data.message, res.status);
    }
    if (err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') {
      return new ApiError('The backend did not respond within 10 seconds.', undefined, true);
    }
    if (!res || res.status >= 500) {
      return new ApiError(
        'Cannot reach the Component 2 backend. Check that it is running on http://localhost:8080.',
        res?.status,
        true
      );
    }
    return new ApiError(`Request failed with status ${res.status}.`, res.status);
  }
  return new ApiError(err instanceof Error ? err.message : 'Unexpected error.');
}

async function get<T>(url: string, signal?: AbortSignal): Promise<T> {
  try {
    const res = await apiClient.get<T>(url, { signal });
    return res.data;
  } catch (err) {
    throw normalizeError(err);
  }
}

export const api = {
  getDeveloper: (id: number | string, signal?: AbortSignal): Promise<Developer> =>
    get<Developer>(`/developers/${id}`, signal),

  getAllDevelopers: (signal?: AbortSignal): Promise<Developer[]> =>
    get<Developer[]>('/developers', signal),

  getSecurityEvents: (developerId: number | string, signal?: AbortSignal): Promise<SecurityEvent[]> =>
    get<SecurityEvent[]>(`/security-events/developer/${developerId}`, signal),

  getInteractions: (developerId: number | string, signal?: AbortSignal): Promise<DeveloperInteraction[]> =>
    get<DeveloperInteraction[]>(`/developer-interactions/developer/${developerId}`, signal),

  getLifecycleHistory: (securityEventId: number | string, signal?: AbortSignal): Promise<LifecycleHistory[]> =>
    get<LifecycleHistory[]>(`/lifecycle/security-event/${securityEventId}`, signal),

  getBehaviourSummary: (developerId: number | string, signal?: AbortSignal): Promise<DeveloperBehaviourSummary> =>
    get<DeveloperBehaviourSummary>(`/developer-behaviour/${developerId}`, signal),

  getResponseSequences: (developerId: number | string, signal?: AbortSignal): Promise<ResponseSequenceAnalysis> =>
    get<ResponseSequenceAnalysis>(`/developer-behaviour/${developerId}/response-sequences`, signal),
};

// ── Quality & Regression Tests (TASKS P1-5) ───────────────────────────────────
// Served by the Vite dev-server plugin (frontend/dev/qualityPlugin.mjs), not by the backend.
// A production build has no such routes; the page then explains how to run the tests.

const qualityClient = axios.create({
  baseURL: '/__c2-quality',
  timeout: 10000,
  headers: {
    Accept: 'application/json',
  },
});

/** Thrown when the page is not served by the local dev server, so no reports can be read. */
export class QualityUnavailableError extends Error {
  constructor() {
    super('Test reports are only available from the local dev server (npm run dev).');
    this.name = 'QualityUnavailableError';
  }
}

function isQualityStatus(data: unknown): data is QualityStatus {
  return typeof data === 'object' && data !== null && (data as QualityStatus).runnerAvailable === true;
}

function normalizeQualityError(err: unknown): Error {
  if (axios.isAxiosError(err)) {
    const res = err.response;
    if (!res || res.status === 404 || res.status === 405) {
      return new QualityUnavailableError();
    }
    if (isErrorResponse(res.data)) {
      return new ApiError(res.data.message, res.status);
    }
    return new ApiError(`Request failed with status ${res.status}.`, res.status);
  }
  return err instanceof Error ? err : new Error('Unexpected error.');
}

export const qualityApi = {
  getStatus: async (signal?: AbortSignal): Promise<QualityStatus> => {
    try {
      const res = await qualityClient.get<unknown>('/report', { signal });
      // A static host answers unknown paths with index.html; only the plugin returns this shape
      if (!isQualityStatus(res.data)) throw new QualityUnavailableError();
      return res.data;
    } catch (err) {
      if (err instanceof QualityUnavailableError) throw err;
      throw normalizeQualityError(err);
    }
  },

  startRun: async (): Promise<TestRunState> => {
    try {
      // The header marks the request as coming from this page; the plugin rejects runs without it
      const res = await qualityClient.post<{ run: TestRunState }>('/run', null, {
        headers: { 'X-C2-Quality': '1' },
      });
      return res.data.run;
    } catch (err) {
      throw normalizeQualityError(err);
    }
  },
};
