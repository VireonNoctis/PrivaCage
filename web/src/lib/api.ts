import type {
  CatalogSummary,
  HealthResponse,
  TrackerCatalog,
  WorkspaceCapabilities
} from './types';

const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '');

export class ApiError extends Error {
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  let response: Response;

  try {
    response = await fetch(apiBaseUrl + path, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      cache: 'no-store',
      signal
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw error;
    }
    throw new ApiError('The Rust API could not be reached. Check that the local backend is running.');
  }

  if (!response.ok) {
    throw new ApiError('The Rust API returned HTTP ' + response.status + '.', response.status);
  }

  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError('The Rust API returned an invalid JSON response.', response.status);
  }
}

export function fetchHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return getJson<HealthResponse>('/api/health', signal);
}

export function fetchCatalogSummary(signal?: AbortSignal): Promise<CatalogSummary> {
  return getJson<CatalogSummary>('/api/v1/summary', signal);
}

export function fetchTrackerCatalog(signal?: AbortSignal): Promise<TrackerCatalog> {
  return getJson<TrackerCatalog>('/api/v1/tracker-catalog', signal);
}

export function fetchCapabilities(signal?: AbortSignal): Promise<WorkspaceCapabilities> {
  return getJson<WorkspaceCapabilities>('/api/v1/capabilities', signal);
}
