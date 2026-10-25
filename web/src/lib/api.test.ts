import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fetchCatalogSummary,
  fetchHealth,
  fetchTrackerCatalog
} from './api';

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(data)
  } as unknown as Response;
}

describe('PrivaCage API client', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('requests the live Rust health endpoint without caching', async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({
        status: 'ok',
        service: 'privacage-web-api',
        backend: 'rust',
        device_connection: 'not_connected'
      })
    );

    const result = await fetchHealth();

    expect(result.backend).toBe('rust');
    expect(fetch).toHaveBeenCalledWith('/api/health', {
      method: 'GET',
      headers: { Accept: 'application/json' },
      cache: 'no-store',
      signal: undefined
    });
  });

  it('returns the catalog summary from the API rather than fabricating counters', async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({
        schema_version: 1,
        updated_at: '2026-10-23',
        total_records: 15,
        active: 10,
        review: 5,
        retired: 0,
        domain_indicators: 19,
        sdk_patterns: 0,
        evidence_sources: 18,
        categories: { analytics: 8 }
      })
    );

    const result = await fetchCatalogSummary();

    expect(result.total_records).toBe(15);
    expect(result.categories.analytics).toBe(8);
  });

  it('surfaces HTTP errors instead of treating them as empty data', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({}, 503));

    await expect(fetchTrackerCatalog()).rejects.toMatchObject({
      name: 'ApiError',
      message: 'The Rust API returned HTTP 503.',
      status: 503
    });
  });

  it('reports malformed JSON clearly', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockRejectedValue(new SyntaxError('invalid json'))
    } as unknown as Response);

    await expect(fetchTrackerCatalog()).rejects.toThrow(
      'The Rust API returned an invalid JSON response.'
    );
  });
});
