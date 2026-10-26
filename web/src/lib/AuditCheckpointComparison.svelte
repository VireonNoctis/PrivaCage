<script lang="ts">
  import {
    compareAuditCheckpoints,
    type AuditCheckpointComparisonReport,
    type AuditCheckpointRelationship
  } from './audit-checkpoint';

  let firstInput = $state<HTMLInputElement | undefined>(undefined);
  let secondInput = $state<HTMLInputElement | undefined>(undefined);
  let firstFile = $state<File | null>(null);
  let secondFile = $state<File | null>(null);
  let comparison = $state<AuditCheckpointComparisonReport | null>(null);
  let error = $state('');
  let busy = $state(false);

  function selectFile(side: 'first' | 'second', event: Event): void {
    const input = event.currentTarget;
    if (!(input instanceof HTMLInputElement)) return;

    const file = input.files?.[0] ?? null;
    if (file && file.size > 2 * 1024 * 1024) {
      error = 'Each checkpoint must be 2 MiB or smaller.';
      input.value = '';
      if (side === 'first') firstFile = null;
      else secondFile = null;
      comparison = null;
      return;
    }

    if (side === 'first') firstFile = file;
    else secondFile = file;

    error = '';
    comparison = null;
  }

  async function compareSelectedCheckpoints(): Promise<void> {
    if (!firstFile || !secondFile || busy) return;

    busy = true;
    error = '';
    comparison = null;
    try {
      const [firstText, secondText] = await Promise.all([
        firstFile.text(),
        secondFile.text()
      ]);
      comparison = await compareAuditCheckpoints(firstText, secondText);
    } catch (cause) {
      error = cause instanceof Error
        ? cause.message
        : 'The selected checkpoints could not be compared.';
    } finally {
      busy = false;
    }
  }

  function relationshipLabel(relationship: AuditCheckpointRelationship): string {
    switch (relationship) {
      case 'same-chain':
        return 'Same verified record chain';
      case 'first-is-prefix':
        return 'Checkpoint A is a strict prefix of checkpoint B';
      case 'second-is-prefix':
        return 'Checkpoint B is a strict prefix of checkpoint A';
      case 'diverged':
        return 'Verified chains diverge';
    }
  }

  function relationshipDescription(relationship: AuditCheckpointRelationship): string {
    switch (relationship) {
      case 'same-chain':
        return 'Both signed files contain the same verified record-hash sequence. Other signed metadata may still differ.';
      case 'first-is-prefix':
        return 'Every record hash in checkpoint A matches the beginning of checkpoint B. B contains additional records after the shared prefix.';
      case 'second-is-prefix':
        return 'Every record hash in checkpoint B matches the beginning of checkpoint A. A contains additional records after the shared prefix.';
      case 'diverged':
        return 'The record-hash sequences share a prefix, then differ. This comparison does not determine which history is authoritative.';
    }
  }
</script>

<section class="audit-import-panel audit-compare-panel" aria-labelledby="audit-compare-title">
  <div class="section-kicker">COMPARISON / LOCAL ONLY</div>
  <h2 id="audit-compare-title">Compare two checkpoints</h2>
  <p>Choose two signed checkpoint files to compare their verified event-chain history. Both files are read in this browser only. They must have the same signer-key fingerprint, date range, time zone, categories and redaction settings.</p>

  <input
    class="sr-only"
    type="file"
    accept=".json,application/json"
    aria-label="Choose first checkpoint for comparison"
    bind:this={firstInput}
    onchange={(event) => selectFile('first', event)}
  />
  <input
    class="sr-only"
    type="file"
    accept=".json,application/json"
    aria-label="Choose second checkpoint for comparison"
    bind:this={secondInput}
    onchange={(event) => selectFile('second', event)}
  />

  <div class="audit-compare-files">
    <article class="audit-compare-file">
      <span>CHECKPOINT A</span>
      <strong title={firstFile?.name ?? 'No file selected'}>{firstFile?.name ?? 'No file selected'}</strong>
      <button class="button button--outline" type="button" onclick={() => firstInput?.click()} disabled={busy}>
        Choose file A
      </button>
    </article>
    <article class="audit-compare-file">
      <span>CHECKPOINT B</span>
      <strong title={secondFile?.name ?? 'No file selected'}>{secondFile?.name ?? 'No file selected'}</strong>
      <button class="button button--outline" type="button" onclick={() => secondInput?.click()} disabled={busy}>
        Choose file B
      </button>
    </article>
  </div>

  <div class="audit-import-actions">
    <button
      class="button button--light"
      type="button"
      onclick={compareSelectedCheckpoints}
      disabled={!firstFile || !secondFile || busy}
    >{busy ? 'Comparing locally …' : 'Verify and compare'} <span aria-hidden="true">↗</span></button>
    <span class="audit-import-note">NO UPLOAD / MAX 2 MIB PER FILE</span>
  </div>

  {#if error}
    <div class="audit-error" role="alert">
      <strong>Comparison unavailable</strong>
      <p>{error}</p>
      <span>Both files must pass signature, payload-digest, schema and event-chain validation before comparison.</span>
    </div>
  {/if}

  {#if comparison}
    <section class="audit-compare-result" aria-live="polite" aria-labelledby="audit-compare-result-title">
      <div class="section-kicker">VERIFIED COMPARISON</div>
      <h3 id="audit-compare-result-title">{relationshipLabel(comparison.relationship)}</h3>
      <p>{relationshipDescription(comparison.relationship)}</p>

      <div class="audit-compare-summary">
        <article class="audit-report-stat">
          <span>SHARED CHAIN PREFIX</span>
          <strong>{comparison.sharedPrefixEvents}</strong>
          <small>Matching record hashes from the beginning</small>
        </article>
        <article class="audit-report-stat">
          <span>EVENTS AFTER PREFIX / A</span>
          <strong>{comparison.firstEventsAfterSharedPrefix}</strong>
          <small>{comparison.first.eventCount} total verified events</small>
        </article>
        <article class="audit-report-stat">
          <span>EVENTS AFTER PREFIX / B</span>
          <strong>{comparison.secondEventsAfterSharedPrefix}</strong>
          <small>{comparison.second.eventCount} total verified events</small>
        </article>
      </div>

      <div class="audit-report-details">
        <div><span>CHECKPOINT A (DEVICE CLOCK)</span><strong>{comparison.first.createdAt}</strong></div>
        <div><span>CHECKPOINT B (DEVICE CLOCK)</span><strong>{comparison.second.createdAt}</strong></div>
      </div>
    </section>
    <p class="audit-compare-boundary">This is a hash-chain comparison, not proof of signer identity, trusted time or event completeness. Event details, queried hostnames and socket-owner labels are not displayed.</p>
  {/if}
</section>
