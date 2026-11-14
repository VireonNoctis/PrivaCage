import type {
  CatalogSummary,
  HealthResponse,
  TrackerCatalog,
  TrackerEntry,
  TrackerEvidence,
  TrackerIndicators,
  WorkspaceCapabilities,
  WorkspaceCapability
} from './types';

const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '');
const MAX_API_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_TRACKER_ENTRIES = 5000;
const MAX_INDICATORS_PER_KIND = 200;
const MAX_EVIDENCE_PER_ENTRY = 25;
const MAX_CATEGORIES = 200;

export class ApiError extends Error {
  readonly status: number | undefined;

  constructor(message: string, status?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isString(value: unknown, maxLength: number, allowEmpty = false): value is string {
  return (
    typeof value === 'string' &&
    value.length <= maxLength &&
    (allowEmpty || value.trim().length > 0) &&
    !/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(value)
  );
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isIsoDate(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(value + 'T00:00:00.000Z');
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

function isHostname(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 253 ||
    value !== value.toLowerCase()
  ) {
    return false;
  }

  return value.split('.').every(
    (label) =>
      label.length > 0 &&
      label.length <= 63 &&
      !label.startsWith('-') &&
      !label.endsWith('-') &&
      /^[a-z0-9-]+$/.test(label)
  );
}

function isSafeEvidenceUrl(value: unknown): value is string {
  if (!isString(value, 2048) || value !== value.trim()) return false;

  try {
    const url = new URL(value);
    return (
      url.protocol === 'https:' &&
      url.hostname.length > 0 &&
      url.username.length === 0 &&
      url.password.length === 0
    );
  } catch {
    return false;
  }
}

function invalidPayload(resource: string): never {
  throw new ApiError('The Rust API returned an invalid ' + resource + ' response.');
}

async function readBoundedText(response: Response): Promise<string> {
  const contentLength = response.headers?.get('content-length');
  if (contentLength && /^\d+$/.test(contentLength) && Number(contentLength) > MAX_API_RESPONSE_BYTES) {
    throw new ApiError('The Rust API response exceeds the 2 MiB limit.', response.status);
  }

  if (!response.body) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_API_RESPONSE_BYTES) {
      throw new ApiError('The Rust API response exceeds the 2 MiB limit.', response.status);
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let byteLength = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      byteLength += value.byteLength;

      if (byteLength > MAX_API_RESPONSE_BYTES) {
        await reader.cancel();
        throw new ApiError('The Rust API response exceeds the 2 MiB limit.', response.status);
      }

      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError('The Rust API response could not be read.', response.status);
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new ApiError('The Rust API returned text that is not valid UTF-8.', response.status);
  }
}

async function getJson<T>(
  path: string,
  validate: (value: unknown) => T,
  signal?: AbortSignal
): Promise<T> {
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

  let rawText: string;
  try {
    rawText = await readBoundedText(response);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError('The Rust API response could not be read.', response.status);
  }

  let value: unknown;
  try {
    value = JSON.parse(rawText) as unknown;
  } catch {
    throw new ApiError('The Rust API returned an invalid JSON response.', response.status);
  }

  return validate(value);
}

function parseHealth(value: unknown): HealthResponse {
  if (
    !isRecord(value) ||
    value.status !== 'ok' ||
    value.service !== 'privacage-web-api' ||
    value.backend !== 'rust' ||
    value.device_connection !== 'not_connected'
  ) {
    return invalidPayload('health');
  }

  return {
    status: 'ok',
    service: 'privacage-web-api',
    backend: 'rust',
    device_connection: 'not_connected'
  };
}

function parseCatalogSummary(value: unknown): CatalogSummary {
  if (
    !isRecord(value) ||
    value.schema_version !== 1 ||
    !isIsoDate(value.updated_at) ||
    !isNonNegativeInteger(value.total_records) ||
    !isNonNegativeInteger(value.active) ||
    !isNonNegativeInteger(value.review) ||
    !isNonNegativeInteger(value.retired) ||
    !isNonNegativeInteger(value.domain_indicators) ||
    !isNonNegativeInteger(value.sdk_patterns) ||
    !isNonNegativeInteger(value.evidence_sources) ||
    !isRecord(value.categories) ||
    Object.keys(value.categories).length > MAX_CATEGORIES
  ) {
    return invalidPayload('tracker summary');
  }

  // Category names come from the API; a null prototype prevents special keys such as
  // __proto__ from changing the accumulator's prototype.
  const categories: Record<string, number> = Object.create(null) as Record<string, number>;
  for (const [name, count] of Object.entries(value.categories)) {
    if (!isString(name, 128) || !isNonNegativeInteger(count)) {
      return invalidPayload('tracker summary');
    }
    categories[name] = count;
  }

  return {
    schema_version: 1,
    updated_at: value.updated_at,
    total_records: value.total_records,
    active: value.active,
    review: value.review,
    retired: value.retired,
    domain_indicators: value.domain_indicators,
    sdk_patterns: value.sdk_patterns,
    evidence_sources: value.evidence_sources,
    categories
  };
}

function parseIndicators(value: unknown): TrackerIndicators | null {
  if (!isRecord(value) || !Array.isArray(value.domains) || !Array.isArray(value.sdk_patterns)) {
    return null;
  }
  if (
    value.domains.length > MAX_INDICATORS_PER_KIND ||
    value.sdk_patterns.length > MAX_INDICATORS_PER_KIND ||
    (value.domains.length === 0 && value.sdk_patterns.length === 0)
  ) {
    return null;
  }

  const domains: string[] = [];
  for (const domain of value.domains) {
    if (!isHostname(domain)) return null;
    domains.push(domain);
  }

  const sdkPatterns: string[] = [];
  for (const pattern of value.sdk_patterns) {
    if (!isString(pattern, 512)) return null;
    sdkPatterns.push(pattern);
  }

  return { domains, sdk_patterns: sdkPatterns };
}

function parseEvidence(value: unknown): TrackerEvidence | null {
  if (
    !isRecord(value) ||
    !isSafeEvidenceUrl(value.url) ||
    !isString(value.description, 2000)
  ) {
    return null;
  }

  return { url: value.url, description: value.description };
}

function parseTrackerEntry(value: unknown): TrackerEntry | null {
  if (
    !isRecord(value) ||
    !isString(value.id, 128) ||
    !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value.id) ||
    !isString(value.name, 300) ||
    !isString(value.category, 128) ||
    (value.confidence !== 'low' && value.confidence !== 'medium' && value.confidence !== 'high') ||
    (value.status !== 'active' && value.status !== 'review' && value.status !== 'retired') ||
    !isIsoDate(value.last_verified) ||
    !Array.isArray(value.evidence) ||
    value.evidence.length === 0 ||
    value.evidence.length > MAX_EVIDENCE_PER_ENTRY
  ) {
    return null;
  }

  const indicators = parseIndicators(value.indicators);
  if (!indicators) return null;

  const evidence: TrackerEvidence[] = [];
  for (const source of value.evidence) {
    const parsedSource = parseEvidence(source);
    if (!parsedSource) return null;
    evidence.push(parsedSource);
  }

  return {
    id: value.id,
    name: value.name,
    category: value.category,
    indicators,
    confidence: value.confidence,
    status: value.status,
    last_verified: value.last_verified,
    evidence
  };
}

function parseTrackerCatalog(value: unknown): TrackerCatalog {
  if (
    !isRecord(value) ||
    value.schema_version !== 1 ||
    !isIsoDate(value.updated_at) ||
    !Array.isArray(value.entries) ||
    value.entries.length > MAX_TRACKER_ENTRIES
  ) {
    return invalidPayload('tracker catalogue');
  }

  const entries: TrackerEntry[] = [];
  const ids = new Set<string>();

  for (const entry of value.entries) {
    const parsedEntry = parseTrackerEntry(entry);
    if (!parsedEntry || ids.has(parsedEntry.id)) return invalidPayload('tracker catalogue');
    ids.add(parsedEntry.id);
    entries.push(parsedEntry);
  }

  return { schema_version: 1, updated_at: value.updated_at, entries };
}

function parseCapability(value: unknown): WorkspaceCapability | null {
  if (
    !isRecord(value) ||
    !isString(value.id, 128) ||
    !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value.id) ||
    !isString(value.title, 200) ||
    !isString(value.explanation, 2000) ||
    (value.status !== 'available' &&
      value.status !== 'not_connected' &&
      value.status !== 'platform_local')
  ) {
    return null;
  }

  return {
    id: value.id,
    title: value.title,
    status: value.status,
    explanation: value.explanation
  };
}

function parseCapabilities(value: unknown): WorkspaceCapabilities {
  if (!isRecord(value) || !Array.isArray(value.capabilities) || value.capabilities.length > 100) {
    return invalidPayload('capabilities');
  }

  const capabilities: WorkspaceCapability[] = [];
  const ids = new Set<string>();

  for (const item of value.capabilities) {
    const capability = parseCapability(item);
    if (!capability || ids.has(capability.id)) return invalidPayload('capabilities');
    ids.add(capability.id);
    capabilities.push(capability);
  }

  return { capabilities };
}

export function fetchHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return getJson('/api/health', parseHealth, signal);
}

export function fetchCatalogSummary(signal?: AbortSignal): Promise<CatalogSummary> {
  return getJson('/api/v1/summary', parseCatalogSummary, signal);
}

export function fetchTrackerCatalog(signal?: AbortSignal): Promise<TrackerCatalog> {
  return getJson('/api/v1/tracker-catalog', parseTrackerCatalog, signal);
}

export function fetchCapabilities(signal?: AbortSignal): Promise<WorkspaceCapabilities> {
  return getJson('/api/v1/capabilities', parseCapabilities, signal);
}
