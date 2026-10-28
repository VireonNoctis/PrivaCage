<script lang="ts">
  import { onMount } from 'svelte';
  import RollingNumber from './lib/RollingNumber.svelte';
  import AuditCheckpointComparison from './lib/AuditCheckpointComparison.svelte';
  import { verifyAuditCheckpoint, type AuditCheckpointReport } from './lib/audit-checkpoint';
  import {
    fetchCapabilities,
    fetchCatalogSummary,
    fetchHealth,
    fetchTrackerCatalog
  } from './lib/api';
  import type {
    CapabilityStatus,
    CatalogSummary,
    HealthResponse,
    TrackerCatalog,
    TrackerStatus,
    WorkspaceCapability
  } from './lib/types';

  type View = 'overview' | 'tracker' | 'activity' | 'audit' | 'platforms' | 'settings';

  const navigation: Array<{ id: View; label: string; glyph: string; description: string }> = [
    { id: 'overview', label: 'Overview', glyph: '⠿', description: 'Workspace overview' },
    { id: 'tracker', label: 'Tracker intelligence', glyph: '◈', description: 'Evidence-linked tracker indicators' },
    { id: 'activity', label: 'Activity log', glyph: '∴', description: 'Device event availability' },
    { id: 'audit', label: 'Audit trail', glyph: '⌁', description: 'Local audit evidence' },
    { id: 'platforms', label: 'Platform boundaries', glyph: '⫶', description: 'Supported and limited capabilities' },
    { id: 'settings', label: 'Settings', glyph: '⌘', description: 'Workspace preferences and service status' }
  ];

  const viewNames: Record<View, string> = {
    overview: 'Overview',
    tracker: 'Tracker intelligence',
    activity: 'Activity log',
    audit: 'Audit trail',
    platforms: 'Platform boundaries',
    settings: 'Settings'
  };

  function formatLocalClock(): string {
    const now = new Date();
    return [now.getHours(), now.getMinutes(), now.getSeconds()]
      .map((part) => String(part).padStart(2, '0'))
      .join(':');
  }

  let localClock = $state(formatLocalClock());
  let activeView = $state<View>('overview');
  let health = $state<HealthResponse | null>(null);
  let summary = $state<CatalogSummary | null>(null);
  let catalog = $state<TrackerCatalog | null>(null);
  let capabilities = $state<WorkspaceCapability[]>([]);
  let loading = $state(true);
  let apiError = $state('');
  let notice = $state('');
  let query = $state('');
  let categoryFilter = $state('all');
  let statusFilter = $state('all');
  let activeEntryId = $state<string | null>(null);
  let reducedMotion = $state(false);
  let auditReport = $state<AuditCheckpointReport | null>(null);
  let auditFileName = $state('');
  let auditError = $state('');
  let auditBusy = $state(false);
  let trustedFingerprint = $state('');
  let auditFileInput = $state<HTMLInputElement | undefined>(undefined);
  let firstLoad = true;
  let requestController: AbortController | null = null;

  let currentViewName = $derived(viewNames[activeView]);

  let trustedFingerprintStatus = $derived.by(() => {
    if (!auditReport || !trustedFingerprint.trim()) return 'not-checked';
    const normalized = trustedFingerprint.trim().replace(/[:\s]/g, '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(normalized)) return 'invalid';
    return normalized === auditReport.signerPublicKeySha256 ? 'match' : 'mismatch';
  });
  let categories = $derived(
    Array.from(new Set((catalog?.entries ?? []).map((entry) => entry.category))).sort()
  );
  let filteredEntries = $derived(
    (catalog?.entries ?? []).filter((entry) => {
      const needle = query.trim().toLowerCase();
      const matchesQuery =
        needle.length === 0 ||
        [
          entry.id,
          entry.name,
          entry.category,
          ...entry.indicators.domains,
          ...entry.indicators.sdk_patterns
        ].some((value) => value.toLowerCase().includes(needle));
      const matchesCategory = categoryFilter === 'all' || entry.category === categoryFilter;
      const matchesStatus = statusFilter === 'all' || entry.status === statusFilter;
      return matchesQuery && matchesCategory && matchesStatus;
    })
  );
  let categoryRanking = $derived(
    Object.entries(summary?.categories ?? {})
      .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
      .slice(0, 6)
  );
  let maxCategoryCount = $derived(Math.max(1, ...Object.values(summary?.categories ?? {})));
  let latestVerified = $derived(
    [...(catalog?.entries ?? [])]
      .sort((left, right) => right.last_verified.localeCompare(left.last_verified))
      .slice(0, 4)
  );

  function readViewFromHash(): void {
    const requested = window.location.hash.replace(/^#/, '') as View;
    activeView = navigation.some((item) => item.id === requested) ? requested : 'overview';
  }

  async function refreshWorkspace(): Promise<void> {
    requestController?.abort();
    const controller = new AbortController();
    requestController = controller;
    loading = true;
    apiError = '';

    try {
      const [healthResult, summaryResult, catalogResult, capabilitiesResult] = await Promise.all([
        fetchHealth(controller.signal),
        fetchCatalogSummary(controller.signal),
        fetchTrackerCatalog(controller.signal),
        fetchCapabilities(controller.signal)
      ]);

      if (controller.signal.aborted) return;
      health = healthResult;
      summary = summaryResult;
      catalog = catalogResult;
      capabilities = capabilitiesResult.capabilities;
      notice = firstLoad ? '' : 'Workspace refreshed from the Rust API.';
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') return;
      apiError =
        error instanceof Error
          ? error.message
          : 'The Rust API could not be reached. No replacement data was generated.';
      health = null;
      summary = null;
      catalog = null;
      capabilities = [];
      notice = '';
    } finally {
      if (requestController === controller) {
        loading = false;
        firstLoad = false;
      }
    }
  }

  function exportCatalog(): void {
    if (!catalog) {
      notice = 'Tracker catalogue is unavailable. Nothing was exported.';
      return;
    }

    try {
      const data = new Blob([JSON.stringify(catalog, null, 2)], {
        type: 'application/json;charset=utf-8'
      });
      const objectUrl = URL.createObjectURL(data);
      const link = document.createElement('a');
      link.href = objectUrl;
      link.download = 'privacage-tracker-catalog-' + catalog.updated_at + '.json';
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      notice = 'The source-backed tracker catalogue was exported locally.';
    } catch {
      notice = 'The browser could not create the catalogue export.';
    }
  }

  async function importAuditCheckpoint(event: Event): Promise<void> {
    const input = event.currentTarget;
    if (!(input instanceof HTMLInputElement)) return;
    const file = input.files?.[0];
    if (!file) return;

    auditBusy = true;
    auditError = '';
    auditReport = null;
    auditFileName = file.name;
    trustedFingerprint = '';

    try {
      if (file.size > 2 * 1024 * 1024) {
        throw new Error('Checkpoint exceeds the 2 MiB input limit.');
      }
      const checkpointText = await file.text();
      auditReport = await verifyAuditCheckpoint(checkpointText);
      notice = 'Checkpoint verified locally in this browser. No file data was uploaded.';
    } catch (error) {
      auditReport = null;
      auditError = error instanceof Error ? error.message : 'Could not verify this audit checkpoint.';
      notice = '';
    } finally {
      auditBusy = false;
      input.value = '';
    }
  }

  async function copyDomain(domain: string): Promise<void> {
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error('Clipboard access is unavailable in this browser context.');
      }
      await navigator.clipboard.writeText(domain);
      notice = 'Copied ' + domain + ' to the clipboard.';
    } catch {
      notice = 'Could not access the clipboard. Select and copy ' + domain + ' manually.';
    }
  }

  function showView(view: View): void {
    activeView = view;
    notice = '';
  }

  function statusLabel(status: TrackerStatus): string {
    if (status === 'active') return 'Active indicator';
    if (status === 'review') return 'Review only';
    return 'Retired';
  }

  function confidenceLabel(confidence: string): string {
    return confidence.charAt(0).toUpperCase() + confidence.slice(1) + ' confidence';
  }

  function capabilityLabel(status: CapabilityStatus): string {
    if (status === 'available') return 'Available';
    if (status === 'platform_local') return 'Platform-local';
    return 'Not connected';
  }

  function capabilityClass(status: CapabilityStatus): string {
    return 'state-pill state-pill--' + status.replace('_', '-');
  }

  onMount(() => {
    readViewFromHash();
    window.addEventListener('hashchange', readViewFromHash);

    const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    reducedMotion = motionQuery.matches;
    const handleMotionChange = (event: MediaQueryListEvent) => {
      reducedMotion = event.matches;
    };
    motionQuery.addEventListener('change', handleMotionChange);

    // The local clock keeps the digit-wheel system visible without relying on API data.
    const clockTimer = window.setInterval(() => {
      localClock = formatLocalClock();
    }, 1000);

    void refreshWorkspace();

    return () => {
      requestController?.abort();
      window.clearInterval(clockTimer);
      window.removeEventListener('hashchange', readViewFromHash);
      motionQuery.removeEventListener('change', handleMotionChange);
    };
  });
</script>

<svelte:head>
  <title>PrivaCage — Privacy, made visible.</title>
  <meta
    name="description"
    content="An evidence-first privacy workspace. Inspect tracker indicators, understand platform boundaries, and never mistake an unavailable signal for an event."
  />
</svelte:head>

<div class:reduce-motion={reducedMotion} class="app-shell">
  <aside class="sidebar" aria-label="PrivaCage workspace">
    <a class="brand-lockup" href="#overview" onclick={() => showView('overview')} aria-label="PrivaCage home">
      <span class="brand-mark" aria-hidden="true">⠿</span>
      <span class="brand-word">PrivaCage<span class="brand-period">.</span></span>
    </a>

    <div class="workspace-caption">PERSONAL PRIVACY WORKSPACE</div>

    <nav class="primary-nav" aria-label="Main navigation">
      <div class="nav-caption">WORKSPACE</div>
      {#each navigation as item, index (item.id)}
        <a
          class:active={activeView === item.id}
          href={'#' + item.id}
          aria-current={activeView === item.id ? 'page' : undefined}
          aria-label={item.description}
          onclick={() => showView(item.id)}
        >
          <span class="nav-glyph" aria-hidden="true">{item.glyph}</span>
          <span class="nav-label">{item.label}</span>
          <span class="nav-index">{String(index + 1).padStart(2, '0')}</span>
        </a>
      {/each}
    </nav>

    <div class="sidebar-foot">
      <div class="api-indicator">
        <span class:online={health?.status === 'ok'} class="status-dot"></span>
        <span class="api-indicator-label">RUST API</span>
        <strong>{health?.status === 'ok' ? 'ONLINE' : loading ? 'CONNECTING' : 'OFFLINE'}</strong>
      </div>
      <div class="sidebar-foot-note">
        <span>LOCAL-FIRST BY DESIGN</span>
        <span>NO PRODUCT TELEMETRY</span>
      </div>
      <div class="version-line"><span>PC / WEB</span><span>v0.1.0</span></div>
    </div>
  </aside>

  <div class="app-main">
    <header class="topbar">
      <div class="breadcrumb"><span>PRIVACAGE</span><span class="breadcrumb-slash">/</span><strong>{currentViewName.toUpperCase()}</strong></div>
      <div class="topbar-actions">
        <div class="topbar-clock">
          <span class="topbar-clock-label">LOCAL TIME</span>
          <strong class="topbar-clock-value">
            <RollingNumber value={localClock} reducedMotion={reducedMotion} announce={false} />
          </strong>
        </div>
        <div class="device-pill"><span class="device-pill-dot"></span> DEVICE NOT LINKED</div>
        <button class="icon-button refresh-button" type="button" onclick={refreshWorkspace} disabled={loading} aria-label="Refresh workspace">
          <span class:spin={loading} class="refresh-glyph" aria-hidden="true">↻</span>
          <span class="refresh-text">{loading ? 'Checking' : 'Refresh'}</span>
        </button>
      </div>
    </header>

    {#if apiError}
      <div class="notice notice--error" role="alert">
        <span class="notice-symbol" aria-hidden="true">!</span>
        <div><strong>Workspace API unavailable</strong><p>{apiError}</p></div>
        <button type="button" class="notice-action" onclick={refreshWorkspace}>Retry ↗</button>
      </div>
    {/if}

    {#if notice}
      <div class="notice notice--info" role="status">
        <span class="notice-symbol" aria-hidden="true">·</span>
        <p>{notice}</p>
        <button type="button" class="notice-close" onclick={() => (notice = '')} aria-label="Dismiss notice">×</button>
      </div>
    {/if}

    <main id="main-content" class="main-content">
      {#if activeView === 'overview'}
        <section class="hero-section">
          <div class="hero-copy">
            <div class="eyebrow"><span class="eyebrow-line"></span> PRIVATE BY DEFAULT <span class="eyebrow-separator">/</span> EVIDENCE FIRST</div>
            <h1>Privacy,<br /><span>made visible.</span></h1>
            <p class="hero-description">
              See what the evidence says. Understand what your platform exposes.
              Keep the difference between a signal and a certainty clear.
            </p>
            <div class="hero-actions">
              <a class="button button--light" href="#tracker" onclick={() => showView('tracker')}>
                Explore tracker intelligence <span aria-hidden="true">↗</span>
              </a>
              <button class="button button--quiet" type="button" onclick={refreshWorkspace} disabled={loading}>
                Refresh workspace <span aria-hidden="true">⟳</span>
              </button>
            </div>
          </div>
          <div class="hero-art" aria-hidden="true">
            <div class="hero-art-corner hero-art-corner--tl"></div>
            <div class="hero-art-corner hero-art-corner--tr"></div>
            <div class="hero-art-corner hero-art-corner--bl"></div>
            <div class="hero-art-corner hero-art-corner--br"></div>
            <div class="hero-glyph">⠿</div>
            <div class="hero-art-rule"></div>
            <span class="hero-art-code">OBSERVE / VERIFY / DECIDE</span>
            <span class="hero-art-coordinates">PC—01</span>
          </div>
          <div class="hero-index"><span>01</span><span>OBSERVABLE PRIVACY</span><span class="hero-index-line"></span><span>WEB CONSOLE</span></div>
        </section>

        <section class="data-boundary-strip" aria-label="Workspace data boundaries">
          <div class="strip-cell"><span class="strip-key">CATALOG SOURCE</span><strong>{summary ? 'REPOSITORY BUNDLE' : 'NOT AVAILABLE'}</strong></div>
          <div class="strip-cell"><span class="strip-key">API STATUS</span><strong class:muted-value={health?.status !== 'ok'}>{health?.status === 'ok' ? 'CONNECTED' : loading ? 'CHECKING' : 'OFFLINE'}</strong></div>
          <div class="strip-cell"><span class="strip-key">DEVICE SESSION</span><strong class="muted-value">NOT CONNECTED</strong></div>
          <div class="strip-stamp">◌ <span>LOCAL WORKSPACE</span></div>
        </section>

        <section class="metric-grid" aria-label="Tracker catalogue summary">
          <article class="metric-card metric-card--primary">
            <div class="metric-top"><span>CATALOG RECORDS</span><span class="metric-glyph">◈</span></div>
            <div class="metric-value">{#if summary}<RollingNumber value={summary.total_records} reducedMotion={reducedMotion} />{:else}<span class="metric-unavailable">—</span>{/if}</div>
            <div class="metric-foot"><span class="metric-foot-mark">↳</span> Evidence-backed entries in the source catalogue</div>
          </article>
          <article class="metric-card">
            <div class="metric-top"><span>ACTIVE INDICATORS</span><span class="metric-status-dot"></span></div>
            <div class="metric-value">{#if summary}<RollingNumber value={summary.active} reducedMotion={reducedMotion} />{:else}<span class="metric-unavailable">—</span>{/if}</div>
            <div class="metric-foot">May be offered for explicit review</div>
          </article>
          <article class="metric-card">
            <div class="metric-top"><span>REVIEW ONLY</span><span class="review-mark">◇</span></div>
            <div class="metric-value">{#if summary}<RollingNumber value={summary.review} reducedMotion={reducedMotion} />{:else}<span class="metric-unavailable">—</span>{/if}</div>
            <div class="metric-foot">Not eligible for active bulk import</div>
          </article>
          <article class="metric-card">
            <div class="metric-top"><span>EVIDENCE SOURCES</span><span class="metric-glyph">↗</span></div>
            <div class="metric-value">{#if summary}<RollingNumber value={summary.evidence_sources} reducedMotion={reducedMotion} />{:else}<span class="metric-unavailable">—</span>{/if}</div>
            <div class="metric-foot">{summary ? 'HTTPS references across the catalogue' : 'Waiting for catalogue response'}</div>
          </article>
        </section>

        <section class="overview-grid">
          <article class="panel category-panel">
            <div class="panel-heading">
              <div><div class="section-kicker">INTELLIGENCE / 01</div><h2>Indicator landscape</h2></div>
              <span class="panel-corner">↗</span>
            </div>
            <p class="panel-description">Distribution of records in the currently loaded tracker catalogue. These are indicators, not confirmed device activity.</p>
            {#if summary && categoryRanking.length > 0}
              <div class="category-bars">
                {#each categoryRanking as category (category[0])}
                  <div class="category-bar-row">
                    <div class="category-bar-label"><span>{category[0].replaceAll('_', ' ')}</span><strong>{category[1].toString().padStart(2, '0')}</strong></div>
                    <div class="bar-track" role="img" aria-label={category[0] + ': ' + category[1] + ' records'}>
                      <div class="bar-fill" style={'width: ' + Math.max(4, Math.round((category[1] / maxCategoryCount) * 100)) + '%'}></div>
                    </div>
                  </div>
                {/each}
              </div>
            {:else if loading}
              <div class="loading-state"><span class="braille-loader" aria-hidden="true">⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏</span><span>Reading canonical catalogue…</span></div>
            {:else}
              <div class="inline-empty">Catalogue counts are unavailable until the Rust API responds.</div>
            {/if}
            {#if summary}
              <div class="panel-bottom-note"><span>{summary.domain_indicators} domain indicators</span><span>{summary.sdk_patterns} SDK patterns</span></div>
            {/if}
          </article>

          <article class="panel connection-panel">
            <div class="panel-heading">
              <div><div class="section-kicker">CONNECTION / 02</div><h2>Workspace integrity</h2></div>
              <span class="integrity-glyph" aria-hidden="true">⠿</span>
            </div>
            <div class="connection-status-row">
              <span class:online={health?.status === 'ok'} class="large-status-dot"></span>
              <div><strong>{health?.status === 'ok' ? 'Rust API responding' : loading ? 'Checking service' : 'API not reachable'}</strong><p>{health?.status === 'ok' ? 'Catalogue endpoints are responding.' : 'Workspace data is not being replaced with sample values.'}</p></div>
            </div>
            <div class="connection-detail"><span>Backend</span><strong>{health?.backend?.toUpperCase() ?? '—'}</strong></div>
            <div class="connection-detail"><span>Device event stream</span><strong class="muted-value">NOT CONNECTED</strong></div>
            <div class="connection-detail"><span>Network enforcement</span><strong class="muted-value">PLATFORM-LOCAL</strong></div>
            <div class="panel-callout"><span aria-hidden="true">i</span><p>The web workspace does not currently pair with the Android app or receive device events. No live activity is shown unless an actual source is connected.</p></div>
          </article>
        </section>

        <section class="verification-panel">
          <div class="panel-heading">
            <div><div class="section-kicker">SOURCE DATES / 03</div><h2>Latest verification dates</h2></div>
            <a class="text-link" href="#tracker" onclick={() => showView('tracker')}>Open catalogue <span aria-hidden="true">↗</span></a>
          </div>
          {#if latestVerified.length > 0}
            <div class="verification-list">
              {#each latestVerified as entry (entry.id)}
                <button class="verification-row" type="button" onclick={() => { activeEntryId = entry.id; showView('tracker'); }}>
                  <span class="verification-symbol" aria-hidden="true">◈</span>
                  <span class="verification-name"><strong>{entry.name}</strong><small>{entry.category.replaceAll('_', ' ')}</small></span>
                  <span class={'status-label status-label--' + entry.status}>{statusLabel(entry.status)}</span>
                  <span class="verification-date">{entry.last_verified}</span>
                  <span class="row-arrow" aria-hidden="true">↗</span>
                </button>
              {/each}
            </div>
          {:else}
            <div class="inline-empty">{loading ? 'Loading verification dates…' : 'No catalogue entries are available.'}</div>
          {/if}
        </section>

        <section class="module-grid">
          <a class="module-card" href="#tracker" onclick={() => showView('tracker')}>
            <span class="module-index">01 / EXPLORE</span><span class="module-glyph" aria-hidden="true">◈</span>
            <h3>Tracker intelligence</h3><p>Review indicators, confidence, status, and the sources that support each entry.</p><span class="module-arrow">Open directory ↗</span>
          </a>
          <a class="module-card" href="#activity" onclick={() => showView('activity')}>
            <span class="module-index">02 / OBSERVE</span><span class="module-glyph" aria-hidden="true">∴</span>
            <h3>Activity log</h3><p>See what is required before a trustworthy live feed can be displayed.</p><span class="module-arrow">View availability ↗</span>
          </a>
          <a class="module-card" href="#platforms" onclick={() => showView('platforms')}>
            <span class="module-index">03 / UNDERSTAND</span><span class="module-glyph" aria-hidden="true">⫶</span>
            <h3>Platform boundaries</h3><p>Separate observable facts from what each operating system keeps out of reach.</p><span class="module-arrow">Read boundaries ↗</span>
          </a>
        </section>

      {:else if activeView === 'tracker'}
        <section class="page-intro">
          <div class="eyebrow"><span class="eyebrow-line"></span> EVIDENCE INDEX / 01</div>
          <h1>Tracker<br /><span>intelligence.</span></h1>
          <p>Search the repository-backed catalogue. Each entry describes an indicator and its evidence, not proof that a particular app collected or transmitted personal data.</p>
          <div class="page-intro-meta"><span>SCHEMA {summary?.schema_version ?? '—'}</span><span>UPDATED {summary?.updated_at ?? '—'}</span><span>{summary?.total_records ?? '—'} RECORDS</span></div>
        </section>

        <section class="directory-toolbar" aria-label="Filter tracker catalogue">
          <label class="search-field"><span aria-hidden="true">⌕</span><input type="search" placeholder="Search names, domains, SDKs…" bind:value={query} aria-label="Search tracker intelligence" /><kbd>SEARCH</kbd></label>
          <label class="filter-field"><span class="sr-only">Category</span>
            <select bind:value={categoryFilter} aria-label="Filter by category">
              <option value="all">All categories</option>
              {#each categories as category (category)}<option value={category}>{category.replaceAll('_', ' ')}</option>{/each}
            </select>
          </label>
          <label class="filter-field"><span class="sr-only">Review status</span>
            <select bind:value={statusFilter} aria-label="Filter by review status">
              <option value="all">All statuses</option>
              <option value="active">Active indicators</option>
              <option value="review">Review only</option>
              <option value="retired">Retired</option>
            </select>
          </label>
          <button class="button button--outline export-button" type="button" onclick={exportCatalog} disabled={!catalog}>Export JSON ↗</button>
        </section>

        <div class="directory-meta"><span>{catalog ? filteredEntries.length + ' MATCHING RECORDS' : 'CATALOGUE UNAVAILABLE'}</span><span>ACTIVE ≠ CONFIRMED TRACKING</span></div>

        {#if loading && !catalog}
          <div class="empty-state"><span class="braille-loader" aria-hidden="true">⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏</span><h2>Loading source catalogue</h2><p>Reading tracker intelligence from the Rust API.</p></div>
        {:else if !catalog}
          <div class="empty-state"><span class="empty-glyph" aria-hidden="true">⠿</span><h2>Catalogue unavailable</h2><p>The source data did not load. Retry the API connection; no local demo entries were substituted.</p><button class="button button--light" type="button" onclick={refreshWorkspace}>Retry connection ↻</button></div>
        {:else if filteredEntries.length === 0}
          <div class="empty-state"><span class="empty-glyph" aria-hidden="true">⌕</span><h2>No matching indicators</h2><p>Change the search text or reset one of the filters to see other catalogue records.</p><button class="button button--outline" type="button" onclick={() => { query = ''; categoryFilter = 'all'; statusFilter = 'all'; }}>Reset filters</button></div>
        {:else}
          <div class="record-list">
            {#each filteredEntries as entry (entry.id)}
              <article class:record-card--expanded={activeEntryId === entry.id} class="record-card">
                <button
                  class="record-card-header"
                  type="button"
                  aria-expanded={activeEntryId === entry.id}
                  aria-controls={'record-details-' + entry.id}
                  onclick={() => (activeEntryId = activeEntryId === entry.id ? null : entry.id)}
                >
                  <span class="record-symbol" aria-hidden="true">◈</span>
                  <span class="record-name-block"><strong>{entry.name}</strong><small>{entry.category.replaceAll('_', ' ')} <span>·</span> {confidenceLabel(entry.confidence)}</small></span>
                  <span class={'status-label status-label--' + entry.status}>{statusLabel(entry.status)}</span>
                  <span class="record-date">VERIFIED {entry.last_verified}</span>
                  <span class="record-chevron" aria-hidden="true">{activeEntryId === entry.id ? '−' : '+'}</span>
                </button>
                {#if activeEntryId === entry.id}
                  <div id={'record-details-' + entry.id} class="record-details">
                    <div class="record-detail-section">
                      <div class="detail-caption">DOMAIN INDICATORS <span>{entry.indicators.domains.length.toString().padStart(2, '0')}</span></div>
                      {#if entry.indicators.domains.length}
                        <div class="domain-list">
                          {#each entry.indicators.domains as domain (domain)}
                            <button type="button" class="domain-chip" onclick={() => copyDomain(domain)} title={'Copy ' + domain}>
                              <span>{domain}</span><span aria-hidden="true">⧉</span>
                            </button>
                          {/each}
                        </div>
                      {:else}<p class="detail-muted">No domain indicators are listed.</p>{/if}
                    </div>
                    <div class="record-detail-section">
                      <div class="detail-caption">STATIC SDK / PACKAGE PATTERNS <span>{entry.indicators.sdk_patterns.length.toString().padStart(2, '0')}</span></div>
                      {#if entry.indicators.sdk_patterns.length}
                        <div class="pattern-list">{#each entry.indicators.sdk_patterns as pattern (pattern)}<code>{pattern}</code>{/each}</div>
                      {:else}<p class="detail-muted">No SDK pattern is listed for this entry.</p>{/if}
                    </div>
                    <div class="record-detail-section record-evidence-section">
                      <div class="detail-caption">EVIDENCE SOURCES <span>{entry.evidence.length.toString().padStart(2, '0')}</span></div>
                      {#each entry.evidence as source, sourceIndex (sourceIndex + '-' + source.url)}
                        <div class="evidence-item">
                          <div class="evidence-index">{String(sourceIndex + 1).padStart(2, '0')}</div>
                          <div class="evidence-copy"><p>{source.description}</p><a href={source.url} target="_blank" rel="noopener noreferrer">{source.url} <span aria-hidden="true">↗</span></a></div>
                        </div>
                      {/each}
                    </div>
                    <p class="record-caveat">Interpretation: this record associates an indicator with a documented service. It does not prove runtime use, payload contents, malicious intent, or which app made a request. Review-only records must not silently become blocking rules.</p>
                  </div>
                {/if}
              </article>
            {/each}
          </div>
        {/if}

      {:else if activeView === 'activity'}
        <section class="page-intro">
          <div class="eyebrow"><span class="eyebrow-line"></span> OBSERVABILITY / 02</div>
          <h1>Only show<br /><span>what happened.</span></h1>
          <p>A trustworthy activity log requires events from a real platform adapter. The web console is not connected to a device event stream, so there are no events to display.</p>
        </section>
        <section class="empty-state empty-state--large">
          <div class="empty-signal" aria-hidden="true"><span>·</span><span>∴</span><span>·</span></div>
          <div class="empty-state-kicker">EVENT SOURCE / UNAVAILABLE</div>
          <h2>No device event stream connected.</h2>
          <p>This isn't a zero-event report. The web workspace does not receive Android DNS history, permission observations, or OS event telemetry. Nothing is fabricated to make the feed look active.</p>
          <div class="boundary-mini-grid">
            <div><span>ANDROID DNS EVENTS</span><strong>DEVICE-LOCAL</strong></div>
            <div><span>WEB EVENT INGESTION</span><strong>NOT CONNECTED</strong></div>
          </div>
          <a class="button button--outline" href="#platforms" onclick={() => showView('platforms')}>Understand platform boundaries ↗</a>
        </section>
        <section class="info-row"><span class="info-symbol">i</span><p>When a supported event source is connected, entries should retain their source, time, decision, and evidence. A domain match alone must never be rendered as proof of data exfiltration.</p></section>

      {:else if activeView === 'audit'}
        <section class="page-intro">
          <div class="eyebrow"><span class="eyebrow-line"></span> INTEGRITY / 03</div>
          <h1>Evidence with<br /><span>provenance.</span></h1>
          <p>Verify a signed Android audit checkpoint offline. The selected file is processed in this browser and is never uploaded by this verifier.</p>
        </section>
        <section class="audit-overview-grid">
          <article class="audit-feature-card">
            <div class="section-kicker">01 / LOCAL HISTORY</div>
            <span class="audit-feature-glyph">⌁</span>
            <h2>Device audit history</h2>
            <p>Android's optional DNS history stays in app-private storage until you explicitly export a checkpoint.</p>
            <span class="status-label status-label--review">Device remains unlinked</span>
          </article>
          <article class="audit-feature-card">
            <div class="section-kicker">02 / INTEGRITY</div>
            <span class="audit-feature-glyph">◈</span>
            <h2>Signed checkpoints</h2>
            <p>Checks the embedded P-256 signature, payload digest, strict schema and every event hash-chain link.</p>
            <span class="status-label status-label--active">Local verification available</span>
          </article>
        </section>
        <section class="audit-import-panel">
          <div class="section-kicker">IMPORT / 01</div>
          <h2>Verify a checkpoint</h2>
          <p>Select a signed checkpoint JSON exported by PrivaCage. Maximum file size: 2 MiB. Verification itself makes no network requests and never uploads the selected file.</p>
          <input
            class="sr-only"
            type="file"
            accept=".json,application/json"
            aria-label="Choose signed audit checkpoint JSON file"
            bind:this={auditFileInput}
            onchange={importAuditCheckpoint}
          />
          <div class="audit-import-actions">
            <button
              class="button button--light"
              type="button"
              onclick={() => auditFileInput?.click()}
              disabled={auditBusy}
            >{auditBusy ? 'Verifying locally …' : 'Choose checkpoint JSON'} <span aria-hidden="true">↗</span></button>
            <span class="audit-import-note">PCAGE AUDIT CHECKPOINT / SCHEMA V1</span>
          </div>
          {#if auditError}
            <div class="audit-error" role="alert">
              <strong>Verification failed</strong>
              <p>{auditError}</p>
              <span>No successful verification is implied. The source file was not modified.</span>
            </div>
          {/if}
        </section>
        {#if auditReport}
          <section class="audit-report" aria-labelledby="audit-report-title">
            <div class="audit-report-heading">
              <div>
                <div class="section-kicker">VERIFICATION RESULT / LOCAL ONLY</div>
                <h2 id="audit-report-title">Checkpoint verified locally</h2>
                <p>{auditFileName}</p>
              </div>
              <span class="status-label status-label--active">All checks passed</span>
            </div>
            <div class="audit-report-grid">
              <article class="audit-report-stat">
                <span>SIGNATURE</span>
                <strong>VALID</strong>
                <small>For the embedded P-256 public key</small>
              </article>
              <article class="audit-report-stat">
                <span>PAYLOAD DIGEST</span>
                <strong>MATCH</strong>
                <small>Exact payload UTF-8 bytes</small>
              </article>
              <article class="audit-report-stat">
                <span>EVENT CHAIN</span>
                <strong>VALID</strong>
                <small>{auditReport.eventCount} event{auditReport.eventCount === 1 ? '' : 's'} checked</small>
              </article>
            </div>
            <div class="audit-report-details">
              <div><span>CHECKPOINT CREATED (DEVICE CLOCK)</span><strong>{auditReport.createdAt}</strong></div>
              <div><span>PAYLOAD GENERATED</span><strong>{auditReport.generatedAt}</strong></div>
              <div><span>FILTER PERIOD</span><strong>{auditReport.startDate} — {auditReport.endDate}</strong></div>
              <div><span>FILTER TIME ZONE</span><strong>{auditReport.filterTimezone}</strong></div>
              <div><span>SELECTED CATEGORIES</span><strong>{auditReport.selectedCategories.join(', ')}</strong></div>
              <div><span>HOSTNAMES</span><strong>{auditReport.redactions.queriedHostnames ? 'REDACTED' : 'INCLUDED IN FILE'}</strong></div>
              <div><span>SOCKET OWNER LABELS</span><strong>{auditReport.redactions.socketOwnerLabels ? 'REDACTED' : 'INCLUDED IN FILE'}</strong></div>
            </div>
            <div class="audit-report-hash">
              <span>PUBLIC-KEY SHA-256 FINGERPRINT</span>
              <code>{auditReport.signerPublicKeySha256}</code>
            </div>
            <div class="audit-report-hash">
              <span>PAYLOAD SHA-256</span>
              <code>{auditReport.payloadSha256}</code>
            </div>
            <div class="audit-report-hash">
              <span>EVENT CHAIN HEAD SHA-256</span>
              <code>{auditReport.chainHeadSha256}</code>
            </div>
            <div class="fingerprint-check">
              <label for="trusted-fingerprint">Expected signer fingerprint (optional)</label>
              <p>Paste a SHA-256 fingerprint obtained through a separate trusted channel. Colons and whitespace are accepted.</p>
              <input
                id="trusted-fingerprint"
                type="text"
                autocomplete="off"
                autocapitalize="off"
                spellcheck="false"
                placeholder="64 hexadecimal characters"
                bind:value={trustedFingerprint}
              />
              {#if trustedFingerprintStatus === 'not-checked'}
                <p class="fingerprint-status">Signer identity has not been independently checked. The embedded key alone does not establish who signed this file.</p>
              {:else if trustedFingerprintStatus === 'invalid'}
                <p class="fingerprint-status">Enter a valid 64-character SHA-256 fingerprint.</p>
              {:else if trustedFingerprintStatus === 'match'}
                <p class="fingerprint-status">Fingerprint matches the supplied value. This establishes trust only if that expected value came from a trusted separate channel.</p>
              {:else}
                <p class="fingerprint-status">Fingerprint mismatch. The signer key differs from the expected fingerprint.</p>
              {/if}
            </div>
          </section>
        {:else if !auditError}
          <section class="empty-state empty-state--compact">
            <span class="empty-glyph" aria-hidden="true">⌁</span>
            <h2>No audit artifact loaded</h2>
            <p>Choose a checkpoint to validate its signature, payload and event chain. No local device history is read automatically and no report is fabricated.</p>
          </section>
        {/if}
        <section class="info-row"><span class="info-symbol">i</span><p>A valid signature means the embedded key signed the checkpoint metadata. It does not establish a person's identity, prove the device clock was correct, or show that every event was recorded. Compare the fingerprint above through a trusted separate channel.</p></section>
        <AuditCheckpointComparison />

      {:else if activeView === 'platforms'}
        <section class="page-intro">
          <div class="eyebrow"><span class="eyebrow-line"></span> CAPABILITY MAP / 04</div>
          <h1>Know the<br /><span>boundary.</span></h1>
          <p>PrivaCage must explain the difference between a capability implemented on a device, a catalogue indicator, and a platform restriction.</p>
        </section>
        <section class="capability-list">
          {#each capabilities as capability (capability.id)}
            <article class="capability-row">
              <div class="capability-symbol" aria-hidden="true">{capability.status === 'available' ? '◈' : capability.status === 'platform_local' ? '⫶' : '∴'}</div>
              <div class="capability-copy"><h2>{capability.title}</h2><p>{capability.explanation}</p></div>
              <span class={capabilityClass(capability.status)}>{capabilityLabel(capability.status)}</span>
            </article>
          {/each}
          {#if capabilities.length === 0}
            <div class="inline-empty">{loading ? 'Loading capability data from the API…' : 'Capability data is unavailable.'}</div>
          {/if}
        </section>

        <section class="platform-grid">
          <article class="platform-card platform-card--current"><div class="platform-card-top"><span>PLATFORM 01</span><span class="platform-mark">A</span></div><h2>Android</h2><p>Contains the early native VPN/DNS adapter, tracker catalogue, local APK inspection, and metadata tools. The UI is functional but still needs emulator and physical-device validation.</p><div class="platform-card-foot"><span class="mini-dot mini-dot--active"></span> IMPLEMENTED, DEVICE VALIDATION PENDING</div></article>
          <article class="platform-card"><div class="platform-card-top"><span>PLATFORM 02</span><span class="platform-mark">i</span></div><h2>iOS</h2><p>The companion is planned around approved Apple APIs and available privacy reports. App binaries and other apps' permissions cannot be freely inspected.</p><div class="platform-card-foot"><span class="mini-dot"></span> PLANNED / SANDBOXED</div></article>
          <article class="platform-card platform-card--current"><div class="platform-card-top"><span>PLATFORM 03</span><span class="platform-mark">W</span></div><h2>Windows</h2><p>The local Go CLI audits selected settings and can preview, apply, verify, and restore documented privacy policies with UAC elevation and a protected rollback backup. Optional outbound blocking can interrupt networking. It does not guarantee zero Windows traffic, and the web console cannot control a PC remotely.</p><div class="platform-card-foot"><span class="mini-dot mini-dot--active"></span> LOCAL AUDIT / REVERSIBLE POLICY CONTROLS</div></article>
          <article class="platform-card"><div class="platform-card-top"><span>PLATFORM 04</span><span class="platform-mark">⌘</span></div><h2>Web console</h2><p>The web client currently exposes repository-backed tracker intelligence and service status. It is not a browser extension and does not monitor other browser tabs or local apps.</p><div class="platform-card-foot"><span class="mini-dot mini-dot--active"></span> CATALOGUE VIEW / READ-ONLY DEVICE STATE</div></article>
        </section>
        <section class="info-row"><span class="info-symbol">i</span><p>Capabilities differ by operating system and deployment privileges. A feature is only labelled as active when a real platform operation and its outcome can be observed.</p></section>

      {:else}
        <section class="page-intro">
          <div class="eyebrow"><span class="eyebrow-line"></span> PREFERENCES / 05</div>
          <h1>Quiet by<br /><span>default.</span></h1>
          <p>Control the web workspace's presentation while keeping its local-first and evidence-first posture visible.</p>
        </section>
        <section class="settings-group">
          <div class="settings-group-heading"><div class="section-kicker">PRESENTATION / 01</div><h2>Interface</h2></div>
          <div class="setting-row"><div class="setting-copy"><strong>Monochrome system</strong><p>The PrivaCage web identity stays black, white, and neutral grey. No colour theme or external font is loaded.</p></div><span class="setting-fixed">FIXED</span></div>
          <div class="setting-row"><div class="setting-copy"><strong>Reduce motion</strong><p>Use the operating system preference by default. You can override it for this browser session.</p></div><label class="switch"><input type="checkbox" bind:checked={reducedMotion} /><span class="switch-track"></span><span class="sr-only">Reduce motion for this session</span></label></div>
        </section>
        <section class="settings-group">
          <div class="settings-group-heading"><div class="section-kicker">CONNECTION / 02</div><h2>Workspace service</h2></div>
          <div class="setting-row"><div class="setting-copy"><strong>Rust API</strong><p>{health?.service ?? 'Service not confirmed'} · The UI requests current data without caching it.</p></div><span class={health?.status === 'ok' ? 'state-pill state-pill--available' : 'state-pill state-pill--not-connected'}>{health?.status === 'ok' ? 'Online' : loading ? 'Checking' : 'Offline'}</span></div>
          <div class="setting-row"><div class="setting-copy"><strong>Tracker catalogue</strong><p>Canonical source: shared/tracker-db/signatures.json. Data is embedded into the API at build time.</p></div><strong class="setting-value">{summary?.updated_at ?? '—'}</strong></div>
          <div class="setting-row"><div class="setting-copy"><strong>Device connection</strong><p>No pairing credential or device event subscription has been configured in this web console.</p></div><span class="state-pill state-pill--not-connected">Not connected</span></div>
          <div class="setting-actions"><button class="button button--outline" type="button" onclick={refreshWorkspace} disabled={loading}>Recheck API status ↻</button><button class="button button--quiet" type="button" onclick={() => { query = ''; categoryFilter = 'all'; statusFilter = 'all'; notice = 'Catalogue search filters reset.'; }}>Reset catalogue filters</button></div>
        </section>
        <section class="settings-group settings-group--last">
          <div class="settings-group-heading"><div class="section-kicker">PRIVACY / 03</div><h2>Product guarantees</h2></div>
          <div class="guarantee-list">
            <div><span>01</span><p>No analytics or product telemetry is integrated in this web client.</p></div>
            <div><span>02</span><p>External evidence links open only when you select a source.</p></div>
            <div><span>03</span><p>When the API is offline, the console shows an unavailable state rather than invented counters.</p></div>
            <div><span>04</span><p>Device-local enforcement and events do not appear in the web workspace unless a real connection is built.</p></div>
          </div>
        </section>
      {/if}

      <footer class="app-footer">
        <a href="#overview" onclick={() => showView('overview')} class="footer-brand"><span aria-hidden="true">⠿</span> PRIVACAGE</a>
        <span>UNDERSTAND WHAT IS EXPOSED.</span>
        <span class="footer-build">LOCAL-FIRST <span>·</span> EVIDENCE-LED</span>
      </footer>
    </main>
  </div>
</div>
