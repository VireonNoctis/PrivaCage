// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App.svelte';
import { fetchCapabilities, fetchCatalogSummary, fetchHealth, fetchTrackerCatalog } from './lib/api';
import { verifyAuditCheckpoint } from './lib/audit-checkpoint';
import type { CatalogSummary, HealthResponse, TrackerCatalog } from './lib/types';

vi.mock('./lib/api', () => ({
  fetchCapabilities: vi.fn(),
  fetchCatalogSummary: vi.fn(),
  fetchHealth: vi.fn(),
  fetchTrackerCatalog: vi.fn()
}));

vi.mock('./lib/audit-checkpoint', () => ({
  verifyAuditCheckpoint: vi.fn()
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
  vi.mocked(verifyAuditCheckpoint).mockReset();
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
    expect(await screen.findByText('Google Analytics collection endpoint')).toBeInTheDocument();
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


  it('verifies an explicitly selected checkpoint locally and offers an independent fingerprint comparison', async () => {
    vi.mocked(verifyAuditCheckpoint).mockResolvedValue({
      createdAt: '2026-10-26T12:00:00Z',
      signerPublicKeySha256: 'a'.repeat(64),
      eventCount: 1,
      chainHeadSha256: 'b'.repeat(64),
      payloadSha256: 'c'.repeat(64),
      generatedAt: '2026-10-26T12:00:00Z',
      filterTimezone: 'UTC',
      startDate: '2026-10-25',
      endDate: '2026-10-25',
      selectedCategories: ['BLOCKED'],
      redactions: { queriedHostnames: true, socketOwnerLabels: true },
      signatureValid: true,
      payloadHashValid: true,
      chainValid: true
    });

    render(App);
    await screen.findByRole('heading', { name: /Privacy, made visible/i });
    await fireEvent.click(screen.getByRole('link', { name: 'Local audit evidence' }));
    await screen.findByRole('heading', { name: /Evidence with/i });

    const input = screen.getByLabelText('Choose signed audit checkpoint JSON file');
    const file = new File(['valid checkpoint json'], 'audit-checkpoint.json', { type: 'application/json' });
    Object.defineProperty(file, 'text', {
      configurable: true,
      value: vi.fn().mockResolvedValue('valid checkpoint json')
    });
    Object.defineProperty(input, 'files', { configurable: true, value: [file] });
    await fireEvent.change(input);

    expect(await screen.findByRole('heading', { name: 'Checkpoint verified locally' })).toBeInTheDocument();
    expect(screen.getByText('PAYLOAD DIGEST')).toBeInTheDocument();
    expect(screen.getByText('EVENT CHAIN')).toBeInTheDocument();
    expect(verifyAuditCheckpoint).toHaveBeenCalledWith('valid checkpoint json');

    expect(screen.getByText(/The embedded key alone does not establish who signed this file/i)).toBeInTheDocument();
    const fingerprint = screen.getByLabelText('Expected signer fingerprint (optional)');
    await fireEvent.input(fingerprint, { target: { value: 'a'.repeat(64) } });
    expect(screen.getByText(/Fingerprint matches the supplied value/i)).toBeInTheDocument();
    expect(screen.getByText(/This establishes trust only if that expected value came from a trusted separate channel/i)).toBeInTheDocument();
  });

  it('surfaces checkpoint verification errors without displaying a valid result', async () => {
    vi.mocked(verifyAuditCheckpoint).mockRejectedValue(
      new Error('Checkpoint signature does not validate against its embedded P-256 public key.')
    );

    render(App);
    await screen.findByRole('heading', { name: /Privacy, made visible/i });
    await fireEvent.click(screen.getByRole('link', { name: 'Local audit evidence' }));
    await screen.findByRole('heading', { name: /Evidence with/i });

    const input = screen.getByLabelText('Choose signed audit checkpoint JSON file');
    const file = new File(['bad checkpoint'], 'invalid.json', { type: 'application/json' });
    Object.defineProperty(file, 'text', {
      configurable: true,
      value: vi.fn().mockResolvedValue('bad checkpoint')
    });
    Object.defineProperty(input, 'files', { configurable: true, value: [file] });
    await fireEvent.change(input);

    expect(await screen.findByRole('alert')).toHaveTextContent('Verification failed');
    expect(screen.queryByRole('heading', { name: 'Checkpoint verified locally' })).not.toBeInTheDocument();
  });

  it('clears stale API-backed content when a workspace refresh fails', async () => {
    render(App);

    expect(await screen.findByText('Google Analytics collection endpoint')).toBeInTheDocument();
    vi.mocked(fetchTrackerCatalog).mockRejectedValueOnce(
      new Error('The Rust API returned an invalid tracker catalogue response.')
    );

    await fireEvent.click(screen.getAllByRole('button', { name: /Refresh workspace/ })[0]);

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The Rust API returned an invalid tracker catalogue response.'
    );
    await waitFor(() => {
      expect(screen.queryByText('Google Analytics collection endpoint')).not.toBeInTheDocument();
    });
    expect(screen.getByText('NOT AVAILABLE')).toBeInTheDocument();
    expect(screen.getByText('DEVICE NOT LINKED')).toBeInTheDocument();
  });

});
