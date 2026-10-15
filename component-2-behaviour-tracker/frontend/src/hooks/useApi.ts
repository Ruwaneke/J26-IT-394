import { useState, useEffect, useCallback } from 'react';
import { normalizeError } from '../api/client';

export interface UseApiResult<T> {
  data: T | undefined;
  error: Error | undefined;
  loading: boolean;
  reload: () => void;
}

export function useApi<T>(
  key: string | null,
  fetcher: (signal: AbortSignal) => Promise<T>
): UseApiResult<T> {
  const [version, setVersion] = useState(0);
  const [state, setState] = useState<{
    key: string | null;
    data: T | undefined;
    error: Error | undefined;
  }>({
    key: null,
    data: undefined,
    error: undefined,
  });

  const activeKey = key === null ? null : `${key}#${version}`;

  useEffect(() => {
    if (activeKey === null) return;
    const controller = new AbortController();

    fetcher(controller.signal)
      .then(data => {
        if (!controller.signal.aborted) {
          setState({ key: activeKey, data, error: undefined });
        }
      })
      .catch(err => {
        if (!controller.signal.aborted) {
          setState({ key: activeKey, data: undefined, error: normalizeError(err) });
        }
      });

    return () => controller.abort();
  }, [activeKey, fetcher]);

  const reload = useCallback(() => {
    setVersion(v => v + 1);
  }, []);

  const isCurrent = state.key === activeKey;

  return {
    data: isCurrent ? state.data : undefined,
    error: isCurrent ? state.error : undefined,
    loading: activeKey !== null && !isCurrent,
    reload,
  };
}
