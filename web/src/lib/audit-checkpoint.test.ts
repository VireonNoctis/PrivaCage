import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { compareAuditCheckpoints, verifyAuditCheckpoint } from './audit-checkpoint';

const sharedCheckpointVector = readFileSync(
  resolve(process.cwd(), '../shared/audit/test-vectors/checkpoint-v1.json'),
  'utf8'
);

const sharedEmptyCheckpointVector = readFileSync(
  resolve(process.cwd(), '../shared/audit/test-vectors/checkpoint-v1-empty.json'),
  'utf8'
);

const sharedMultiEventCheckpointVector = readFileSync(
  resolve(process.cwd(), '../shared/audit/test-vectors/checkpoint-v1-multi-event.json'),
  'utf8'
);

const cryptoProvider = webcrypto as unknown as Crypto;
const encoder = new TextEncoder();
const zeroHash = '0'.repeat(64);

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((length, part) => length + part.length, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  return joined;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function asArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}

function base64(bytes: Uint8Array | ArrayBuffer): string {
  const value: Uint8Array = ArrayBuffer.isView(bytes)
    ? new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    : new Uint8Array(bytes as ArrayBuffer);
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function sha256(value: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await cryptoProvider.subtle.digest('SHA-256', asArrayBuffer(value))));
}

function encodeDerInteger(input: Uint8Array): Uint8Array {
  let firstNonZero = 0;
  while (firstNonZero < input.length - 1 && input[firstNonZero] === 0) firstNonZero += 1;
  const strippedValue = input.slice(firstNonZero);
  const value: Uint8Array = (strippedValue[0] & 0x80) !== 0
    ? concatBytes(new Uint8Array([0]), strippedValue)
    : strippedValue;
  return concatBytes(new Uint8Array([0x02, value.length]), value);
}

function rawEcdsaToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) throw new Error('Expected a 64-byte WebCrypto P-256 signature.');
  const r = encodeDerInteger(raw.slice(0, 32));
  const s = encodeDerInteger(raw.slice(32, 64));
  const body = concatBytes(r, s);
  return concatBytes(new Uint8Array([0x30, body.length]), body);
}

function signingBytes(
  createdAt: string,
  payloadSha256: string,
  chainHeadSha256: string,
  eventCount: number,
  signerPublicKeySha256: string
): Uint8Array {
  return encoder.encode(
    'PrivaCage-Audit-Checkpoint-v1\n' +
    'schema_version=1\n' +
    'signature_algorithm=SHA256withECDSA\n' +
    'created_at=' + createdAt + '\n' +
    'payload_sha256=' + payloadSha256 + '\n' +
    'chain_head_sha256=' + chainHeadSha256 + '\n' +
    'event_count=' + eventCount + '\n' +
    'signer_public_key_sha256=' + signerPublicKeySha256 + '\n'
  );
}

async function createTestKeyPair(): Promise<CryptoKeyPair> {
  return await cryptoProvider.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  ) as CryptoKeyPair;
}

async function createCheckpoint(options: {
  breakEventHash?: boolean;
  keyPair?: CryptoKeyPair;
  eventTimestamps?: string[];
} = {}): Promise<string> {
  const keyPair = options.keyPair ?? await createTestKeyPair();
  const publicKey = await cryptoProvider.subtle.exportKey('spki', keyPair.publicKey);
  const signerFingerprint = await sha256(new Uint8Array(publicKey));
  const createdAt = '2026-10-26T12:00:00Z';
  const timestamps = options.eventTimestamps ?? ['2026-10-25T12:00:00Z'];
  const events: Array<Record<string, string>> = [];
  let previousHash = zeroHash;

  for (let index = 0; index < timestamps.length; index += 1) {
    const eventForHash = {
      timestamp: timestamps[index],
      local_date: '2026-10-25',
      category: 'BLOCKED',
      queried_hostname: '[REDACTED]',
      socket_owner_label: '[REDACTED]'
    };
    const recordMaterial = concatBytes(
      encoder.encode('PrivaCage-Audit-Record-v1\n' + previousHash + '\n'),
      ...[
        eventForHash.timestamp,
        eventForHash.local_date,
        eventForHash.category,
        eventForHash.queried_hostname,
        eventForHash.socket_owner_label
      ].flatMap((field) => {
        const bytes = encoder.encode(field);
        return [encoder.encode(String(bytes.length) + ':'), bytes, encoder.encode('\n')];
      })
    );
    const recordHash = await sha256(recordMaterial);
    events.push({
      ...eventForHash,
      timestamp: options.breakEventHash && index === 0
        ? '2026-10-25T12:00:01Z'
        : eventForHash.timestamp,
      previous_record_sha256: previousHash,
      record_sha256: recordHash
    });
    previousHash = recordHash;
  }

  const eventCount = events.length;
  const chainHead = previousHash;

  // Preserve this exact JSON string: its UTF-8 bytes are what Android signs.
  const payloadJson = JSON.stringify({
    schema_version: 1,
    source: 'optional_local_dns_event_history',
    generated_at: createdAt,
    filter_timezone: 'UTC',
    date_range: { start_inclusive: '2026-10-25', end_inclusive: '2026-10-25' },
    selected_categories: ['BLOCKED'],
    integrity: {
      algorithm: 'sha256-chain-v1',
      genesis_sha256: zeroHash,
      chain_head_sha256: chainHead,
      record_count: eventCount
    },
    redactions: {
      queried_hostnames: true,
      socket_owner_labels: true,
      device_identifiers: true,
      internal_file_paths: true,
      packet_payloads: true
    },
    records_read: eventCount,
    records_skipped_invalid: 0,
    records_excluded_by_filters: 0,
    event_count: eventCount,
    events
  });

  const payloadSha256 = await sha256(encoder.encode(payloadJson));
  const rawSignature = new Uint8Array(await cryptoProvider.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    asArrayBuffer(signingBytes(createdAt, payloadSha256, chainHead, eventCount, signerFingerprint))
  ));
  const signatureDer = rawEcdsaToDer(rawSignature);

  return JSON.stringify({
    format: 'privacage-audit-checkpoint',
    schema_version: 1,
    signature_algorithm: 'SHA256withECDSA',
    created_at: createdAt,
    signer_public_key_x509_base64: base64(publicKey),
    signer_public_key_sha256: signerFingerprint,
    payload_sha256: payloadSha256,
    chain_head_sha256: chainHead,
    event_count: eventCount,
    signature_base64: base64(signatureDer),
    payload_json: payloadJson
  });
}

describe('local signed audit checkpoint verifier', () => {
  it('verifies the shared checkpoint vector also consumed by the Rust verifier', async () => {
    const report = await verifyAuditCheckpoint(sharedCheckpointVector, cryptoProvider);

    expect(report.signatureValid).toBe(true);
    expect(report.payloadHashValid).toBe(true);
    expect(report.chainValid).toBe(true);
    expect(report.createdAt).toBe('2026-10-24T10:01:00Z');
    expect(report.eventCount).toBe(1);
    expect(report.chainHeadSha256).toBe('ebdef2e58dba2dda4942283befe0b5913101be88f35d7e2521c319e42273fecb');
    expect(report.signerPublicKeySha256).toBe('11086649cd3e5d1892200a4200b165bbea5c9f9b47ca83792d4f9a1ef0dc8921');
  });

  it('verifies shared empty-chain and multi-event checkpoint vectors', async () => {
    const empty = await verifyAuditCheckpoint(sharedEmptyCheckpointVector, cryptoProvider);
    expect(empty.signatureValid).toBe(true);
    expect(empty.payloadHashValid).toBe(true);
    expect(empty.chainValid).toBe(true);
    expect(empty.eventCount).toBe(0);
    expect(empty.chainHeadSha256).toBe(zeroHash);

    const multi = await verifyAuditCheckpoint(sharedMultiEventCheckpointVector, cryptoProvider);
    expect(multi.signatureValid).toBe(true);
    expect(multi.payloadHashValid).toBe(true);
    expect(multi.chainValid).toBe(true);
    expect(multi.eventCount).toBe(2);
    expect(multi.chainHeadSha256).toBe('04c0491ab7f904353ce466c16cd48aeaa4e5baba6032570a2e661cacb6ed1eaf');
  });

  it('rejects the shared vector after the same payload mutation tested by Android and Rust', async () => {
    const modifiedCheckpoint = sharedCheckpointVector.replaceAll('[REDACTED]', 'private.example');

    await expect(verifyAuditCheckpoint(modifiedCheckpoint, cryptoProvider))
      .rejects.toThrow('Embedded payload SHA-256 does not match the signed digest.');
  });

  it('verifies a valid Android-format P-256 checkpoint and event chain', async () => {
    const checkpoint = await createCheckpoint();

    const report = await verifyAuditCheckpoint(checkpoint, cryptoProvider);

    expect(report.signatureValid).toBe(true);
    expect(report.payloadHashValid).toBe(true);
    expect(report.chainValid).toBe(true);
    expect(report.eventCount).toBe(1);
    expect(report.signerPublicKeySha256).toMatch(/^[0-9a-f]{64}$/);
    expect(report.redactions).toEqual({ queriedHostnames: true, socketOwnerLabels: true });
  });

  it('rejects a modified payload whose recorded digest was not updated', async () => {
    const envelope = JSON.parse(await createCheckpoint()) as { payload_json: string };
    envelope.payload_json = envelope.payload_json.replace('"filter_timezone":"UTC"', '"filter_timezone":"Etc/UTC"');

    await expect(verifyAuditCheckpoint(JSON.stringify(envelope), cryptoProvider))
      .rejects.toThrow('Embedded payload SHA-256 does not match the signed digest.');
  });

  it('rejects changed event content even when the modified payload is re-signed', async () => {
    const checkpoint = await createCheckpoint({ breakEventHash: true });

    await expect(verifyAuditCheckpoint(checkpoint, cryptoProvider))
      .rejects.toThrow('Record hash mismatch at event 1.');
  });

  it('rejects duplicate JSON object keys instead of accepting parser-dependent data', async () => {
    const checkpoint = await createCheckpoint();
    const ambiguous = checkpoint.replace(
      '"format":"privacage-audit-checkpoint"',
      '"format":"privacage-audit-checkpoint","format":"privacage-audit-checkpoint"'
    );

    await expect(verifyAuditCheckpoint(ambiguous, cryptoProvider))
      .rejects.toThrow('Checkpoint JSON contains a duplicate object key.');
  });

  it('rejects inputs over the documented checkpoint size limit before parsing', async () => {
    await expect(verifyAuditCheckpoint(' '.repeat(2 * 1024 * 1024 + 1), cryptoProvider))
      .rejects.toThrow('Checkpoint exceeds the 2 MiB input limit.');
  });

  it('compares identical verified checkpoints without showing event details', async () => {
    const comparison = await compareAuditCheckpoints(
      sharedCheckpointVector,
      sharedCheckpointVector,
      cryptoProvider
    );

    expect(comparison.relationship).toBe('same-chain');
    expect(comparison.sharedPrefixEvents).toBe(1);
    expect(comparison.firstEventsAfterSharedPrefix).toBe(0);
    expect(comparison.secondEventsAfterSharedPrefix).toBe(0);
  });

  it('recognizes append-only chain extensions and divergent histories for the same signer', async () => {
    const keyPair = await createTestKeyPair();
    const firstTimestamp = '2026-10-25T12:00:00Z';
    const secondTimestamp = '2026-10-25T12:00:01Z';
    const alternateTimestamp = '2026-10-25T12:00:02Z';
    const first = await createCheckpoint({
      keyPair,
      eventTimestamps: [firstTimestamp]
    });
    const extended = await createCheckpoint({
      keyPair,
      eventTimestamps: [firstTimestamp, secondTimestamp]
    });
    const alternate = await createCheckpoint({
      keyPair,
      eventTimestamps: [firstTimestamp, alternateTimestamp]
    });

    const extension = await compareAuditCheckpoints(first, extended, cryptoProvider);
    expect(extension.relationship).toBe('first-is-prefix');
    expect(extension.sharedPrefixEvents).toBe(1);
    expect(extension.firstEventsAfterSharedPrefix).toBe(0);
    expect(extension.secondEventsAfterSharedPrefix).toBe(1);

    const reverseExtension = await compareAuditCheckpoints(extended, first, cryptoProvider);
    expect(reverseExtension.relationship).toBe('second-is-prefix');

    const divergence = await compareAuditCheckpoints(extended, alternate, cryptoProvider);
    expect(divergence.relationship).toBe('diverged');
    expect(divergence.sharedPrefixEvents).toBe(1);
    expect(divergence.firstEventsAfterSharedPrefix).toBe(1);
    expect(divergence.secondEventsAfterSharedPrefix).toBe(1);
  });

  it('refuses to infer chain continuity across different signer keys', async () => {
    const independentCheckpoint = await createCheckpoint();

    await expect(compareAuditCheckpoints(
      sharedCheckpointVector,
      independentCheckpoint,
      cryptoProvider
    )).rejects.toThrow('different signer public keys');
  });

});
