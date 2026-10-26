import { webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { verifyAuditCheckpoint } from './audit-checkpoint';

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

async function sha256(value: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await cryptoProvider.subtle.digest('SHA-256', value)));
}

function encodeDerInteger(input: Uint8Array): Uint8Array {
  let firstNonZero = 0;
  while (firstNonZero < input.length - 1 && input[firstNonZero] === 0) firstNonZero += 1;
  let value = input.slice(firstNonZero);
  if ((value[0] & 0x80) !== 0) value = concatBytes(new Uint8Array([0]), value);
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

async function createCheckpoint(options: { breakEventHash?: boolean } = {}): Promise<string> {
  const keyPair = await cryptoProvider.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  ) as CryptoKeyPair;
  const publicKey = await cryptoProvider.subtle.exportKey('spki', keyPair.publicKey);
  const signerFingerprint = await sha256(new Uint8Array(publicKey));
  const createdAt = '2026-10-26T12:00:00Z';
  const timestamp = '2026-10-25T12:00:00Z';

  const eventForHash = {
    timestamp,
    local_date: '2026-10-25',
    category: 'BLOCKED',
    queried_hostname: '[REDACTED]',
    socket_owner_label: '[REDACTED]'
  };

  const recordMaterial = concatBytes(
    encoder.encode('PrivaCage-Audit-Record-v1\n' + zeroHash + '\n'),
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
  const chainEvent = {
    ...eventForHash,
    timestamp: options.breakEventHash ? '2026-10-25T12:00:01Z' : timestamp,
    previous_record_sha256: zeroHash,
    record_sha256: recordHash
  };

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
      chain_head_sha256: recordHash,
      record_count: 1
    },
    redactions: {
      queried_hostnames: true,
      socket_owner_labels: true,
      device_identifiers: true,
      internal_file_paths: true,
      packet_payloads: true
    },
    records_read: 1,
    records_skipped_invalid: 0,
    records_excluded_by_filters: 0,
    event_count: 1,
    events: [chainEvent]
  });

  const payloadSha256 = await sha256(encoder.encode(payloadJson));
  const rawSignature = new Uint8Array(await cryptoProvider.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    signingBytes(createdAt, payloadSha256, recordHash, 1, signerFingerprint)
  ));
  const signatureDer = rawEcdsaToDer(rawSignature);

  return JSON.stringify({
    format: 'privacage-audit-checkpoint',
    schema_version: 1,
    signature_algorithm: 'SHA256withECDSA',
    created_at: createdAt,
    signer_public_key_x509_base64: Buffer.from(publicKey).toString('base64'),
    signer_public_key_sha256: signerFingerprint,
    payload_sha256: payloadSha256,
    chain_head_sha256: recordHash,
    event_count: 1,
    signature_base64: Buffer.from(signatureDer).toString('base64'),
    payload_json: payloadJson
  });
}

describe('local signed audit checkpoint verifier', () => {
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
});
