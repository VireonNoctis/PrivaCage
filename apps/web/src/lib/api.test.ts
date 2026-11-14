import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  fetchCapabilities,
  fetchCatalogSummary,
  fetchHealth,
  fetchTrackerCatalog
} from './api';

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: vi.fn().mockReturnValue(null) },
    body: null,
    text: vi.fn().mockResolvedValue(JSON.stringify(data))
  } as unknown as Response;
}

function trackerCatalog(overrides: Record<string, unknown> = {}): unknown {
  return {
    schema_version: 1,
    updated_at: '2026-10-23',
    entries: [
      {
        id: 'example-analytics-sdk',
        name: 'Example analytics SDK',
        category: 'analytics',
        indicators: {
          domains: ['collect.example.test'],
          sdk_patterns: ['com.example.analytics.']
        },
        confidence: 'medium',
        status: 'active',
        last_verified: '2026-10-22',
        evidence: [
          {
            url: 'https://example.test/privacy-documentation',
            description: 'Publisher documentation describing the endpoint.'
          }
        ]
      }
    ],
    ...overrides
  };
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

  it('validates tracker catalogue entries and preserves source evidence', async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse(trackerCatalog()));

    const result = await fetchTrackerCatalog();

    expect(result.entries).toHaveLength(1);
    expect(result.entries[0].indicators.domains).toEqual(['collect.example.test']);
    expect(result.entries[0].evidence[0].url).toBe('https://example.test/privacy-documentation');
  });

  it('rejects an unsafe evidence URL instead of exposing it as a clickable source', async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        trackerCatalog({
          entries: [
            {
              ...(trackerCatalog() as { entries: Record<string, unknown>[] }).entries[0],
              evidence: [{ url: 'javascript:alert(1)', description: 'Untrusted link' }]
            }
          ]
        })
      )
    );

    await expect(fetchTrackerCatalog()).rejects.toMatchObject({
      name: 'ApiError',
      message: 'The Rust API returned an invalid tracker catalogue response.'
    });
  });

  it('rejects duplicate tracker IDs that could collide in keyed UI lists', async () => {
    const entry = (trackerCatalog() as { entries: unknown[] }).entries[0];
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(trackerCatalog({ entries: [entry, entry] }))
    );

    await expect(fetchTrackerCatalog()).rejects.toThrow(
      'The Rust API returned an invalid tracker catalogue response.'
    );
  });

  it('rejects invalid dates and unsupported status values', async () => {
    const original = (trackerCatalog() as { entries: Record<string, unknown>[] }).entries[0];
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        trackerCatalog({
          entries: [{ ...original, status: 'probably-safe', last_verified: '2026-02-31' }]
        })
      )
    );

    await expect(fetchTrackerCatalog()).rejects.toThrow(
      'The Rust API returned an invalid tracker catalogue response.'
    );
  });

  it('rejects oversized API responses before parsing them', async () => {
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: vi.fn().mockReturnValue(null) },
      body: null,
      text: vi.fn().mockResolvedValue('x'.repeat(2 * 1024 * 1024 + 1))
    } as unknown as Response);

    await expect(fetchTrackerCatalog()).rejects.toMatchObject({
      name: 'ApiError',
      message: 'The Rust API response exceeds the 2 MiB limit.'
    });
  });

  it('validates capability statuses and IDs instead of trusting arbitrary API JSON', async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({
        capabilities: [
          {
            id: 'device-monitor',
            title: 'Device monitor',
            status: 'active-everything',
            explanation: 'This status is outside the public API schema.'
          }
        ]
      })
    );

    await expect(fetchCapabilities()).rejects.toThrow(
      'The Rust API returned an invalid capabilities response.'
    );
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
      headers: { get: vi.fn().mockReturnValue(null) },
      body: null,
      text: vi.fn().mockResolvedValue('{not valid json')
    } as unknown as Response);

    await expect(fetchTrackerCatalog()).rejects.toThrow(
      'The Rust API returned an invalid JSON response.'
    );
  });

  it('rejects tracker indicators that are not valid hostnames', async () => {
    const original = (trackerCatalog() as { entries: Record<string, unknown>[] }).entries[0];
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        trackerCatalog({
          entries: [
            {
              ...original,
              indicators: { domains: ['metrics..example.test'], sdk_patterns: ['com.example.sdk'] }
            }
          ]
        })
      )
    );

    await expect(fetchTrackerCatalog()).rejects.toThrow(
      'The Rust API returned an invalid tracker catalogue response.'
    );
  });

  it('rejects HTTPS evidence URLs containing credentials', async () => {
    const original = (trackerCatalog() as { entries: Record<string, unknown>[] }).entries[0];
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse(
        trackerCatalog({
          entries: [
            {
              ...original,
              evidence: [
                {
                  url: 'https://user:secret@example.test/privacy',
                  description: 'Credential-bearing evidence URL'
                }
              ]
            }
          ]
        })
      )
    );

    await expect(fetchTrackerCatalog()).rejects.toThrow(
      'The Rust API returned an invalid tracker catalogue response.'
    );
  });

  it('rejects summary payloads with negative numeric counts', async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({
        schema_version: 1,
        updated_at: '2026-10-23',
        total_records: 10,
        active: -1,
        review: 2,
        retired: 0,
        domain_indicators: 4,
        sdk_patterns: 1,
        evidence_sources: 8,
        categories: { analytics: 10 }
      })
    );

    await expect(fetchCatalogSummary()).rejects.toThrow(
      'The Rust API returned an invalid tracker summary response.'
    );
  });

  it('bounds the number of summary categories before they reach the UI', async () => {
    const categories = Object.fromEntries(
      Array.from({ length: 201 }, (_, index) => ['category-' + index, 1])
    );
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({
        schema_version: 1,
        updated_at: '2026-10-23',
        total_records: 201,
        active: 201,
        review: 0,
        retired: 0,
        domain_indicators: 201,
        sdk_patterns: 0,
        evidence_sources: 201,
        categories
      })
    );

    await expect(fetchCatalogSummary()).rejects.toThrow(
      'The Rust API returned an invalid tracker summary response.'
    );
  });

  it('enforces the byte limit while reading a streamed fetch response', async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(1024 * 1024));
        controller.enqueue(new Uint8Array(1024 * 1024));
        controller.enqueue(new Uint8Array([0]));
        controller.close();
      }
    });
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: vi.fn().mockReturnValue(null) },
      body
    } as unknown as Response);

    await expect(fetchTrackerCatalog()).rejects.toMatchObject({
      name: 'ApiError',
      message: 'The Rust API response exceeds the 2 MiB limit.'
    });
  });

});
