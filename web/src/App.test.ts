// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import { fetchCapabilities, fetchCatalogSummary, fetchHealth, fetchTrackerCatalog } from './lib/api';
import type { CatalogSummary, HealthResponse, TrackerCatalog } from './lib/types';

vi.mock('./lib/api', () => ({
  fetchCapabilities: vi.fn(),
  fetchCatalogSummary: vi.fn(),
  fetchHealth: vi.fn(),
  fetchTrackerCatalog: vi.fn()
}));

const health: HealthResponse = {
  status: 'ok',
  service: 'privacage-web-api',
  backend: 'rust',
  device_connection: 'not_connected'
};

const catalog: TrackerCatalog = {
  schema_version: 1,
  updated_at: '2026-10-23',
  entries: [
    {
      id: 'google-analytics-collection',
      name: 'Google Analytics collection endpoint',
      category: 'analytics',
      indicators: { domains: ['google-analytics.com'], sdk_patterns: [] },
      confidence: 'high',
      status: 'active',
      last_verified: '2026-10-21',
      evidence: [{
        url: 'https://developers.google.com/analytics/',
        description: 'Test evidence: a source-backed service endpoint.'
      }]
    },
    {
      id: 'microsoft-clarity-collection',
      name: 'Microsoft Clarity collection endpoint',
      category: 'behavioral_analytics',
      indicators: { domains: ['www.clarity.ms'], sdk_patterns: [] },
      confidence: 'high',
      status: 'active',
      last_verified: '2026-10-23',
      evidence: [{
        url: 'https://learn.microsoft.com/en-us/clarity/',
        description: 'Test evidence: a source-backed service endpoint.'
      }]
    }
  ]
};

const summary: CatalogSummary = {
  schema_version: 1,
  updated_at: '2026-10-23',
  total_records: 2,
  active: 2,
  review: 0,
  retired: 0,
  domain_indicators: 2,
  sdk_patterns: 0,
  evidence_sources: 2,
  categories: { analytics: 1, behavioral_analytics: 1 }
};

beforeEach(() => {
  window.location.hash = '';
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: vi.fn().mockImplementation((media: string) => ({
      matches: false,
      media,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn()
    }))
  });
  vi.mocked(fetchHealth).mockResolvedValue(health);
  vi.mocked(fetchCatalogSummary).mockResolvedValue(summary);
  vi.mocked(fetchTrackerCatalog).mockResolvedValue(catalog);
  vi.mocked(fetchCapabilities).mockResolvedValue({
    capabilities: [
      {
        id: 'tracker-intelligence',
        title: 'Tracker intelligence',
        status: 'available',
        explanation: 'Catalog loaded.'
      },
      {
        id: 'device-activity',
        title: 'Live device activity',
        status: 'not_connected',
        explanation: 'No activity events are generated here.'
      }
    ]
  });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('PrivaCage web workspace', () => {
  it('renders actual API catalogue summary and makes the device boundary visible', async () => {
    render(App);

    expect(await screen.findByRole('heading', { name: /Privacy, made visible/i })).toBeInTheDocument();
    expect(screen.getByText('DEVICE NOT LINKED')).toBeInTheDocument();
    expect(screen.getByText('Google Analytics collection endpoint')).toBeInTheDocument();
    expect(screen.getByText('NO PRODUCT TELEMETRY')).toBeInTheDocument();
  });

  it('navigates to the tracker directory and filters entries by their domain', async () => {
    render(App);

    await screen.findByRole('heading', { name: /Privacy, made visible/i });
    await fireEvent.click(screen.getByRole('link', { name: 'Evidence-linked tracker indicators' }));
    await screen.findByRole('heading', { name: /Tracker intelligence/i });

    const search = screen.getByRole('searchbox', { name: 'Search tracker intelligence' });
    await fireEvent.input(search, { target: { value: 'www.clarity.ms' } });

    await waitFor(() => {
      expect(screen.getByText('Microsoft Clarity collection endpoint')).toBeInTheDocument();
      expect(screen.queryByText('Google Analytics collection endpoint')).not.toBeInTheDocument();
    });
  });
});
