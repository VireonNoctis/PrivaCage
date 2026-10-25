export type TrackerStatus = 'active' | 'review' | 'retired';
export type Confidence = 'low' | 'medium' | 'high';

export interface TrackerEvidence {
  url: string;
  description: string;
}

export interface TrackerIndicators {
  domains: string[];
  sdk_patterns: string[];
}

export interface TrackerEntry {
  id: string;
  name: string;
  category: string;
  indicators: TrackerIndicators;
  confidence: Confidence;
  status: TrackerStatus;
  last_verified: string;
  evidence: TrackerEvidence[];
}

export interface TrackerCatalog {
  schema_version: number;
  updated_at: string;
  entries: TrackerEntry[];
}

export interface CatalogSummary {
  schema_version: number;
  updated_at: string;
  total_records: number;
  active: number;
  review: number;
  retired: number;
  domain_indicators: number;
  sdk_patterns: number;
  evidence_sources: number;
  categories: Record<string, number>;
}

export interface HealthResponse {
  status: 'ok';
  service: string;
  backend: 'rust';
  device_connection: 'not_connected';
}

export type CapabilityStatus = 'available' | 'not_connected' | 'platform_local';

export interface WorkspaceCapability {
  id: string;
  title: string;
  status: CapabilityStatus;
  explanation: string;
}

export interface WorkspaceCapabilities {
  capabilities: WorkspaceCapability[];
}
