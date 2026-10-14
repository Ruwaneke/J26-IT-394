import axios, { AxiosError } from 'axios';
import {
  Developer,
  SecurityEvent,
  DeveloperInteraction,
  LifecycleHistory,
  DeveloperBehaviourSummary,
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
};
