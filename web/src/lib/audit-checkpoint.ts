export interface AuditCheckpointReport {
  createdAt: string;
  signerPublicKeySha256: string;
  eventCount: number;
  chainHeadSha256: string;
  payloadSha256: string;
  generatedAt: string;
  filterTimezone: string;
  startDate: string;
  endDate: string;
  selectedCategories: string[];
  redactions: {
    queriedHostnames: boolean;
    socketOwnerLabels: boolean;
  };
  signatureValid: true;
  payloadHashValid: true;
  chainValid: true;
}

const MAX_CHECKPOINT_BYTES = 2 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 1024 * 1024;
const MAX_EVENTS = 100;
const CHECKPOINT_FORMAT = 'privacage-audit-checkpoint';
const CHECKPOINT_SCHEMA_VERSION = 1;
const CHECKPOINT_SIGNATURE_ALGORITHM = 'SHA256withECDSA';
const CHAIN_ALGORITHM = 'sha256-chain-v1';
const SOURCE = 'optional_local_dns_event_history';
const RECORD_DOMAIN = 'PrivaCage-Audit-Record-v1';
const CHECKPOINT_DOMAIN = 'PrivaCage-Audit-Checkpoint-v1';
const GENESIS_SHA256 = '0'.repeat(64);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const encoder = new TextEncoder();

type JsonObject = Record<string, unknown>;

function fail(message: string): never {
  throw new Error(message);
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function objectWithKeys(value: unknown, expectedKeys: string[], label: string): JsonObject {
  if (!isObject(value)) return fail(label + ' must be a JSON object.');

  const expected = new Set(expectedKeys);
  const actual = Object.keys(value);
  const unknown = actual.find((key) => !expected.has(key));
  const missing = expectedKeys.find((key) => !Object.prototype.hasOwnProperty.call(value, key));

  if (unknown) return fail(label + ' contains unsupported field "' + unknown + '".');
  if (missing) return fail(label + ' is missing required field "' + missing + '".');
  return value;
}

function stringField(value: JsonObject, key: string, label: string, maxLength = 8192): string {
  const field = value[key];
  if (typeof field !== 'string' || field.length > maxLength) {
    return fail(label + '.' + key + ' must be a string within the supported size limit.');
  }
  return field;
}

function integerField(value: JsonObject, key: string, label: string, maximum = MAX_EVENTS): number {
  const field = value[key];
  if (typeof field !== 'number' || !Number.isSafeInteger(field) || field < 0 || field > maximum) {
    return fail(label + '.' + key + ' is outside the supported integer range.');
  }
  return field;
}

function booleanField(value: JsonObject, key: string, label: string): boolean {
  const field = value[key];
  if (typeof field !== 'boolean') return fail(label + '.' + key + ' must be a boolean.');
  return field;
}

function assertDigest(value: string, label: string): void {
  if (!SHA256_PATTERN.test(value)) {
    fail(label + ' must be 64 lowercase hexadecimal characters.');
  }
}

function utf8Length(value: string): number {
  return encoder.encode(value).byteLength;
}

function parseBase64(value: string, label: string, maximumEncodedLength: number): Uint8Array {
  if (
    value.length === 0 ||
    value.length > maximumEncodedLength ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    return fail(label + ' is not valid bounded standard Base64.');
  }

  try {
    const decoded = atob(value);
    const bytes = new Uint8Array(decoded.length);
    for (let index = 0; index < decoded.length; index += 1) {
      bytes[index] = decoded.charCodeAt(index);
    }
    return bytes;
  } catch {
    return fail(label + ' could not be decoded.');
  }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function hexLower(bytes: Uint8Array): string {
  let output = '';
  for (const byte of bytes) output += byte.toString(16).padStart(2, '0');
  return output;
}

async function sha256Hex(bytes: Uint8Array, subtle: SubtleCrypto): Promise<string> {
  const digest = await subtle.digest('SHA-256', toArrayBuffer(bytes));
  return hexLower(new Uint8Array(digest));
}

function readJsonString(source: string, cursor: { index: number }): string {
  const start = cursor.index;
  if (source[cursor.index] !== '"') fail('Checkpoint JSON is malformed.');
  cursor.index += 1;

  while (cursor.index < source.length) {
    const character = source[cursor.index];
    cursor.index += 1;

    if (character === '\\') {
      if (cursor.index >= source.length) fail('Checkpoint JSON is malformed.');
      cursor.index += 1;
    } else if (character === '"') {
      return source.slice(start, cursor.index);
    }
  }

  return fail('Checkpoint JSON contains an unterminated string.');
}

/**
 * JSON.parse silently accepts duplicate object keys. Checkpoint verification must reject them
 * because different parsers may otherwise verify different interpretations of the same file.
 */
function assertNoDuplicateObjectKeys(source: string): void {
  const cursor = { index: 0 };

  function whitespace(): void {
    while (cursor.index < source.length && /[\u0009\u000a\u000d\u0020]/.test(source[cursor.index])) {
      cursor.index += 1;
    }
  }

  function scanValue(depth: number): void {
    if (depth > 64) fail('Checkpoint JSON is nested too deeply.');
    whitespace();

    const character = source[cursor.index];
    if (character === '{') {
      cursor.index += 1;
      whitespace();
      const keys = new Set<string>();
      if (source[cursor.index] === '}') {
        cursor.index += 1;
        return;
      }

      while (cursor.index < source.length) {
        whitespace();
        const rawKey = readJsonString(source, cursor);
        let key: unknown;
        try {
          key = JSON.parse(rawKey);
        } catch {
          fail('Checkpoint JSON contains an invalid object key.');
        }
        if (typeof key !== 'string') fail('Checkpoint JSON contains an invalid object key.');
        if (keys.has(key)) fail('Checkpoint JSON contains a duplicate object key.');
        keys.add(key);

        whitespace();
        if (source[cursor.index] !== ':') fail('Checkpoint JSON is malformed.');
        cursor.index += 1;
        scanValue(depth + 1);
        whitespace();

        if (source[cursor.index] === '}') {
          cursor.index += 1;
          return;
        }
        if (source[cursor.index] !== ',') fail('Checkpoint JSON is malformed.');
        cursor.index += 1;
      }
      fail('Checkpoint JSON contains an unterminated object.');
    }

    if (character === '[') {
      cursor.index += 1;
      whitespace();
      if (source[cursor.index] === ']') {
        cursor.index += 1;
        return;
      }

      while (cursor.index < source.length) {
        scanValue(depth + 1);
        whitespace();
        if (source[cursor.index] === ']') {
          cursor.index += 1;
          return;
        }
        if (source[cursor.index] !== ',') fail('Checkpoint JSON is malformed.');
        cursor.index += 1;
      }
      fail('Checkpoint JSON contains an unterminated array.');
    }

    if (character === '"') {
      readJsonString(source, cursor);
      return;
    }

    const start = cursor.index;
    while (
      cursor.index < source.length &&
      !/[\u0009\u000a\u000d\u0020,\]}]/.test(source[cursor.index])
    ) {
      cursor.index += 1;
    }
    if (cursor.index === start) fail('Checkpoint JSON is malformed.');
  }

  scanValue(0);
  whitespace();
  if (cursor.index !== source.length) fail('Checkpoint JSON contains trailing data.');
}

function parseStrictJson(source: string, label: string): unknown {
  try {
    assertNoDuplicateObjectKeys(source);
    return JSON.parse(source);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Checkpoint JSON')) throw error;
    return fail(label + ' is not valid strict JSON.');
  }
}

function parseCanonicalDate(value: string, label: string): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return fail(label + ' must use canonical YYYY-MM-DD format.');
  }
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  const date = new Date(Date.UTC(year, month - 1, day));
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() + 1 !== month ||
    date.getUTCDate() !== day
  ) {
    return fail(label + ' is not a real calendar date.');
  }
  return value;
}

function parseCanonicalUtcInstant(value: string, label: string): Date {
  if (value.length > 40 || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3}|\.\d{6}|\.\d{9})?Z$/.test(value)) {
    return fail(label + ' must be a bounded canonical UTC instant ending in Z.');
  }

  const dateText = value.slice(0, 10);
  parseCanonicalDate(dateText, label);
  const hour = Number(value.slice(11, 13));
  const minute = Number(value.slice(14, 16));
  const second = Number(value.slice(17, 19));
  const fraction = value.includes('.') ? value.slice(value.indexOf('.') + 1, -1) : '';

  if (
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    (fraction.length > 0 &&
      (fraction === '000' || ((fraction.length === 6 || fraction.length === 9) && fraction.endsWith('000'))))
  ) {
    return fail(label + ' is not a canonical UTC instant.');
  }

  const milliseconds = fraction ? Number((fraction + '000').slice(0, 3)) : 0;
  const parsed = new Date(Date.UTC(
    Number(value.slice(0, 4)),
    Number(value.slice(5, 7)) - 1,
    Number(value.slice(8, 10)),
    hour,
    minute,
    second,
    milliseconds
  ));
  if (!Number.isFinite(parsed.getTime())) return fail(label + ' is not a valid UTC instant.');
  return parsed;
}

function dateAtTimezone(value: Date, timezone: string): string {
  let formatter: Intl.DateTimeFormat;
  try {
    formatter = new Intl.DateTimeFormat('en-CA', {
      timeZone: timezone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    });
  } catch {
    return fail('Audit payload time zone is invalid.');
  }

  const parts = formatter.formatToParts(value);
  const part = (type: string): string => parts.find((item) => item.type === type)?.value ?? '';
  return part('year').padStart(4, '0') + '-' + part('month') + '-' + part('day');
}

function validateHostname(value: string, index: number): void {
  if (value.length === 0 || utf8Length(value) > 253 || !/^[\x00-\x7f]+$/.test(value) || value !== value.toLowerCase()) {
    fail('Event ' + index + ' hostname is empty, too long, or not normalized ASCII.');
  }
  const labels = value.split('.');
  if (labels.some((label) =>
    label.length === 0 ||
    label.length > 63 ||
    label.startsWith('-') ||
    label.endsWith('-') ||
    !/^[a-z0-9-]+$/.test(label)
  )) {
    fail('Event ' + index + ' hostname is not a valid normalized domain.');
  }
}

function derEcdsaToP1363(signature: Uint8Array): Uint8Array {
  let cursor = 0;

  function readLength(): number {
    if (cursor >= signature.length) fail('Checkpoint ECDSA signature is malformed.');
    const first = signature[cursor++];
    if (first < 0x80) return first;

    const count = first & 0x7f;
    if (count === 0 || count > 2 || cursor + count > signature.length || signature[cursor] === 0) {
      fail('Checkpoint ECDSA signature has an invalid DER length.');
    }
    let length = 0;
    for (let index = 0; index < count; index += 1) length = (length << 8) | signature[cursor++];
    if (length < 0x80) fail('Checkpoint ECDSA signature has a non-canonical DER length.');
    return length;
  }

  if (signature.length < 8 || signature[cursor++] !== 0x30) {
    return fail('Checkpoint ECDSA signature is not a DER sequence.');
  }
  const sequenceLength = readLength();
  if (cursor + sequenceLength !== signature.length) {
    return fail('Checkpoint ECDSA signature has inconsistent DER lengths.');
  }

  function readInteger(): Uint8Array {
    if (cursor >= signature.length || signature[cursor++] !== 0x02) {
      return fail('Checkpoint ECDSA signature is missing an integer.');
    }
    const length = readLength();
    if (length === 0 || cursor + length > signature.length) {
      return fail('Checkpoint ECDSA signature contains an invalid integer.');
    }

    let value = signature.slice(cursor, cursor + length);
    cursor += length;
    if ((value[0] & 0x80) !== 0) fail('Checkpoint ECDSA integer is negative.');

    if (value.length > 1 && value[0] === 0) {
      if ((value[1] & 0x80) === 0) fail('Checkpoint ECDSA integer has unnecessary leading zeroes.');
      value = value.slice(1);
    }
    if (value.length > 32) fail('Checkpoint ECDSA integer exceeds the P-256 field size.');

    const padded = new Uint8Array(32);
    padded.set(value, 32 - value.length);
    return padded;
  }

  const r = readInteger();
  const s = readInteger();
  if (cursor !== signature.length) fail('Checkpoint ECDSA signature contains trailing data.');
  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

function signingBytes(
  createdAt: string,
  payloadSha256: string,
  chainHeadSha256: string,
  eventCount: number,
  signerPublicKeySha256: string
): string {
  return CHECKPOINT_DOMAIN + '\n' +
    'schema_version=' + CHECKPOINT_SCHEMA_VERSION + '\n' +
    'signature_algorithm=' + CHECKPOINT_SIGNATURE_ALGORITHM + '\n' +
    'created_at=' + createdAt + '\n' +
    'payload_sha256=' + payloadSha256 + '\n' +
    'chain_head_sha256=' + chainHeadSha256 + '\n' +
    'event_count=' + eventCount + '\n' +
    'signer_public_key_sha256=' + signerPublicKeySha256 + '\n';
}

async function recordDigest(
  previousHash: string,
  event: JsonObject,
  subtle: SubtleCrypto
): Promise<string> {
  const fields = [
    stringField(event, 'timestamp', 'Audit event', 40),
    stringField(event, 'local_date', 'Audit event', 10),
    stringField(event, 'category', 'Audit event', 32),
    stringField(event, 'queried_hostname', 'Audit event', 4096),
    stringField(event, 'socket_owner_label', 'Audit event', 4096)
  ];
  const chunks: Uint8Array[] = [
    encoder.encode(RECORD_DOMAIN + '\n' + previousHash + '\n')
  ];

  for (const field of fields) {
    const bytes = encoder.encode(field);
    chunks.push(encoder.encode(String(bytes.byteLength) + ':'));
    chunks.push(bytes);
    chunks.push(encoder.encode('\n'));
  }

  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const material = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    material.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return sha256Hex(material, subtle);
}

async function verifyPayload(
  payloadJson: string,
  outerHead: string,
  outerEventCount: number,
  subtle: SubtleCrypto
): Promise<{
  generatedAt: string;
  filterTimezone: string;
  startDate: string;
  endDate: string;
  selectedCategories: string[];
  redactions: { queriedHostnames: boolean; socketOwnerLabels: boolean };
}> {
  const payload = objectWithKeys(
    parseStrictJson(payloadJson, 'Embedded audit payload'),
    [
      'schema_version',
      'source',
      'generated_at',
      'filter_timezone',
      'date_range',
      'selected_categories',
      'integrity',
      'redactions',
      'records_read',
      'records_skipped_invalid',
      'records_excluded_by_filters',
      'event_count',
      'events'
    ],
    'Audit payload'
  );

  if (payload.schema_version !== 1 || payload.source !== SOURCE) {
    fail('Unsupported audit payload schema or source.');
  }

  const generatedAt = stringField(payload, 'generated_at', 'Audit payload', 40);
  parseCanonicalUtcInstant(generatedAt, 'Payload generation time');
  const filterTimezone = stringField(payload, 'filter_timezone', 'Audit payload', 128);
  if (!filterTimezone || /[\u0000-\u001f\u007f]/.test(filterTimezone)) {
    fail('Audit payload time zone is missing or invalid.');
  }
  // Validate the time zone even when there are no events.
  dateAtTimezone(new Date(0), filterTimezone);

  const dateRange = objectWithKeys(
    payload.date_range,
    ['start_inclusive', 'end_inclusive'],
    'Audit payload date range'
  );
  const startDate = parseCanonicalDate(
    stringField(dateRange, 'start_inclusive', 'Date range', 10),
    'Audit start date'
  );
  const endDate = parseCanonicalDate(
    stringField(dateRange, 'end_inclusive', 'Date range', 10),
    'Audit end date'
  );
  if (startDate > endDate) fail('Audit payload date range is reversed.');

  if (!Array.isArray(payload.selected_categories) || payload.selected_categories.length === 0) {
    fail('Audit payload selected-category list is empty or malformed.');
  }
  const selectedCategories = payload.selected_categories.map((category) => {
    if (typeof category !== 'string' || !['BLOCKED', 'FORWARDED'].includes(category)) {
      return fail('Audit payload contains an unsupported selected category.');
    }
    return category;
  });
  for (let index = 1; index < selectedCategories.length; index += 1) {
    if (selectedCategories[index - 1] >= selectedCategories[index]) {
      fail('Audit payload selected categories must be unique and sorted.');
    }
  }

  const integrity = objectWithKeys(
    payload.integrity,
    ['algorithm', 'genesis_sha256', 'chain_head_sha256', 'record_count'],
    'Integrity metadata'
  );
  const integrityHead = stringField(integrity, 'chain_head_sha256', 'Integrity metadata', 64);
  const integrityCount = integerField(integrity, 'record_count', 'Integrity metadata');
  if (
    integrity.algorithm !== CHAIN_ALGORITHM ||
    integrity.genesis_sha256 !== GENESIS_SHA256 ||
    integrityHead !== outerHead ||
    integrityCount !== outerEventCount ||
    payload.event_count !== outerEventCount ||
    !Array.isArray(payload.events) ||
    payload.events.length !== outerEventCount
  ) {
    fail('Checkpoint and payload integrity metadata disagree.');
  }

  const recordsRead = integerField(payload, 'records_read', 'Audit payload');
  const recordsSkipped = integerField(payload, 'records_skipped_invalid', 'Audit payload');
  const recordsExcluded = integerField(payload, 'records_excluded_by_filters', 'Audit payload');
  const payloadEventCount = integerField(payload, 'event_count', 'Audit payload');
  if (recordsSkipped + recordsExcluded + payloadEventCount !== recordsRead) {
    fail('Audit payload record counters do not account for the bounded history.');
  }

  const redactions = objectWithKeys(
    payload.redactions,
    ['queried_hostnames', 'socket_owner_labels', 'device_identifiers', 'internal_file_paths', 'packet_payloads'],
    'Redaction metadata'
  );
  const queriedHostnames = booleanField(redactions, 'queried_hostnames', 'Redaction metadata');
  const socketOwnerLabels = booleanField(redactions, 'socket_owner_labels', 'Redaction metadata');
  if (
    !booleanField(redactions, 'device_identifiers', 'Redaction metadata') ||
    !booleanField(redactions, 'internal_file_paths', 'Redaction metadata') ||
    !booleanField(redactions, 'packet_payloads', 'Redaction metadata')
  ) {
    fail('Audit payload makes a false fixed-redaction claim.');
  }

  let previousHash = GENESIS_SHA256;
  for (let index = 0; index < payload.events.length; index += 1) {
    const event = objectWithKeys(
      payload.events[index],
      [
        'timestamp',
        'local_date',
        'category',
        'queried_hostname',
        'socket_owner_label',
        'previous_record_sha256',
        'record_sha256'
      ],
      'Audit event ' + (index + 1)
    );

    const timestamp = stringField(event, 'timestamp', 'Audit event', 40);
    const timestampDate = parseCanonicalUtcInstant(timestamp, 'Event timestamp');
    const localDate = parseCanonicalDate(
      stringField(event, 'local_date', 'Audit event', 10),
      'Event local date'
    );

    if (
      localDate < startDate ||
      localDate > endDate ||
      dateAtTimezone(timestampDate, filterTimezone) !== localDate
    ) {
      fail('Event ' + (index + 1) + ' date is inconsistent with its timestamp or filter range.');
    }

    const category = stringField(event, 'category', 'Audit event', 32);
    if (!selectedCategories.includes(category) || !['BLOCKED', 'FORWARDED'].includes(category)) {
      fail('Event ' + (index + 1) + ' category was not selected for export.');
    }

    const hostname = stringField(event, 'queried_hostname', 'Audit event', 4096);
    if (queriedHostnames) {
      if (hostname !== '[REDACTED]') {
        fail('Event ' + (index + 1) + ' contains a hostname despite the redaction claim.');
      }
    } else {
      validateHostname(hostname, index + 1);
    }

    const ownerLabel = stringField(event, 'socket_owner_label', 'Audit event', 4096);
    if (socketOwnerLabels) {
      if (ownerLabel !== '[REDACTED]') {
        fail('Event ' + (index + 1) + ' contains a socket-owner label despite the redaction claim.');
      }
    } else if (
      ownerLabel.length === 0 ||
      utf8Length(ownerLabel) > 4096 ||
      /[\u0000-\u001f\u007f]/.test(ownerLabel)
    ) {
      fail('Event ' + (index + 1) + ' contains an invalid or oversized socket-owner label.');
    }

    const previousRecordSha256 = stringField(event, 'previous_record_sha256', 'Audit event', 64);
    const recordSha256 = stringField(event, 'record_sha256', 'Audit event', 64);
    assertDigest(previousRecordSha256, 'Event previous hash');
    assertDigest(recordSha256, 'Event record hash');
    if (previousRecordSha256 !== previousHash) {
      fail('Previous-hash mismatch at event ' + (index + 1) + '.');
    }

    const calculated = await recordDigest(previousHash, event, subtle);
    if (calculated !== recordSha256) fail('Record hash mismatch at event ' + (index + 1) + '.');
    previousHash = calculated;
  }

  if (previousHash !== outerHead) fail('Event chain head does not match the signed checkpoint.');

  return {
    generatedAt,
    filterTimezone,
    startDate,
    endDate,
    selectedCategories,
    redactions: { queriedHostnames, socketOwnerLabels }
  };
}

export async function verifyAuditCheckpoint(
  checkpointText: string,
  cryptoProvider: Crypto = globalThis.crypto
): Promise<AuditCheckpointReport> {
  if (checkpointText.length > MAX_CHECKPOINT_BYTES) {
    fail('Checkpoint exceeds the 2 MiB input limit.');
  }

  const checkpointBytes = encoder.encode(checkpointText);
  if (checkpointBytes.byteLength > MAX_CHECKPOINT_BYTES) {
    fail('Checkpoint exceeds the 2 MiB input limit.');
  }
  if (!cryptoProvider?.subtle) fail('Browser cryptographic verification is unavailable.');

  const envelope = objectWithKeys(
    parseStrictJson(checkpointText, 'Checkpoint'),
    [
      'format',
      'schema_version',
      'signature_algorithm',
      'created_at',
      'signer_public_key_x509_base64',
      'signer_public_key_sha256',
      'payload_sha256',
      'chain_head_sha256',
      'event_count',
      'signature_base64',
      'payload_json'
    ],
    'Checkpoint'
  );

  if (envelope.format !== CHECKPOINT_FORMAT || envelope.schema_version !== CHECKPOINT_SCHEMA_VERSION) {
    fail('Unsupported PrivaCage audit checkpoint format or schema version.');
  }
  if (envelope.signature_algorithm !== CHECKPOINT_SIGNATURE_ALGORITHM) {
    fail('Unsupported checkpoint signature algorithm.');
  }

  const createdAt = stringField(envelope, 'created_at', 'Checkpoint', 40);
  parseCanonicalUtcInstant(createdAt, 'Checkpoint creation time');

  const payloadSha256 = stringField(envelope, 'payload_sha256', 'Checkpoint', 64);
  const chainHeadSha256 = stringField(envelope, 'chain_head_sha256', 'Checkpoint', 64);
  const signerPublicKeySha256 = stringField(envelope, 'signer_public_key_sha256', 'Checkpoint', 64);
  assertDigest(payloadSha256, 'Payload SHA-256');
  assertDigest(chainHeadSha256, 'Chain-head SHA-256');
  assertDigest(signerPublicKeySha256, 'Signer-key SHA-256');

  const eventCount = integerField(envelope, 'event_count', 'Checkpoint');
  const payloadJson = stringField(envelope, 'payload_json', 'Checkpoint', MAX_PAYLOAD_BYTES);
  if (utf8Length(payloadJson) > MAX_PAYLOAD_BYTES) {
    fail('Embedded audit payload exceeds the 1 MiB limit.');
  }

  const calculatedPayloadSha256 = await sha256Hex(encoder.encode(payloadJson), cryptoProvider.subtle);
  if (calculatedPayloadSha256 !== payloadSha256) {
    fail('Embedded payload SHA-256 does not match the signed digest.');
  }

  const publicKeyBytes = parseBase64(
    stringField(envelope, 'signer_public_key_x509_base64', 'Checkpoint', 512),
    'Checkpoint public key',
    512
  );
  if (publicKeyBytes.byteLength > 384) fail('Decoded public key exceeds the size limit.');
  const actualFingerprint = await sha256Hex(publicKeyBytes, cryptoProvider.subtle);
  if (actualFingerprint !== signerPublicKeySha256) {
    fail('Signer public-key fingerprint does not match the key bytes.');
  }

  let publicKey: CryptoKey;
  try {
    publicKey = await cryptoProvider.subtle.importKey(
      'spki',
      toArrayBuffer(publicKeyBytes),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
  } catch {
    return fail('Signer key is not a supported P-256 SubjectPublicKeyInfo public key.');
  }

  const signatureBytes = parseBase64(
    stringField(envelope, 'signature_base64', 'Checkpoint', 256),
    'Checkpoint signature',
    256
  );
  if (signatureBytes.byteLength > 128) fail('Decoded ECDSA signature exceeds the size limit.');

  const rawSignature = derEcdsaToP1363(signatureBytes);
  const bytesToVerify = encoder.encode(signingBytes(
    createdAt,
    payloadSha256,
    chainHeadSha256,
    eventCount,
    signerPublicKeySha256
  ));

  let signatureValid = false;
  try {
    signatureValid = await cryptoProvider.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      toArrayBuffer(rawSignature),
      toArrayBuffer(bytesToVerify)
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) {
    fail('Checkpoint signature does not validate against its embedded P-256 public key.');
  }

  const verifiedPayload = await verifyPayload(
    payloadJson,
    chainHeadSha256,
    eventCount,
    cryptoProvider.subtle
  );

  return {
    createdAt,
    signerPublicKeySha256: actualFingerprint,
    eventCount,
    chainHeadSha256,
    payloadSha256: calculatedPayloadSha256,
    generatedAt: verifiedPayload.generatedAt,
    filterTimezone: verifiedPayload.filterTimezone,
    startDate: verifiedPayload.startDate,
    endDate: verifiedPayload.endDate,
    selectedCategories: verifiedPayload.selectedCategories,
    redactions: verifiedPayload.redactions,
    signatureValid: true,
    payloadHashValid: true,
    chainValid: true
  };
}
