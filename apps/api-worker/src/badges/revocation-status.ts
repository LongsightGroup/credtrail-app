import type { JsonObject } from '@credtrail/core-domain';
import { bytesToBase64Url } from '../utils/crypto';

const BITSTRING_STATUS_LIST_CONTEXT = 'https://w3id.org/vc/status-list/bsl/v1';

interface StatusListEntryReference extends JsonObject {
  id: string;
  type: 'BitstringStatusListEntry';
  statusPurpose: 'revocation';
  statusListIndex: string;
  statusListCredential: string;
}

export interface RevocationStatusBitEntry {
  statusListIndex: number;
  revoked: boolean;
}

const gzipBytes = async (bytes: Uint8Array): Promise<Uint8Array> => {
  const normalizedBytes = Uint8Array.from(bytes);
  const sourceStream = new ReadableStream<BufferSource>({
    start(controller): void {
      controller.enqueue(normalizedBytes);
      controller.close();
    },
  });
  const compressedStream = sourceStream.pipeThrough(new CompressionStream('gzip'));
  const compressedBuffer = await new Response(compressedStream).arrayBuffer();
  return new Uint8Array(compressedBuffer);
};

const base64UrlToBytes = (value: string): Uint8Array | null => {
  if (value.trim().length === 0) {
    return null;
  }

  const normalizedBase64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const paddedBase64 = `${normalizedBase64}${'='.repeat((4 - (normalizedBase64.length % 4)) % 4)}`;

  try {
    const raw = atob(paddedBase64);
    const bytes = new Uint8Array(raw.length);

    for (let index = 0; index < raw.length; index += 1) {
      bytes[index] = raw.charCodeAt(index);
    }

    return bytes;
  } catch {
    return null;
  }
};

const gunzipBytes = async (bytes: Uint8Array): Promise<Uint8Array | null> => {
  try {
    const normalizedBytes = Uint8Array.from(bytes);
    const sourceStream = new ReadableStream<BufferSource>({
      start(controller): void {
        controller.enqueue(normalizedBytes);
        controller.close();
      },
    });
    const decompressedStream = sourceStream.pipeThrough(new DecompressionStream('gzip'));
    const decompressedBuffer = await new Response(decompressedStream).arrayBuffer();
    return new Uint8Array(decompressedBuffer);
  } catch {
    return null;
  }
};

export const revocationStatusListPathForTenant = (tenantId: string): string => {
  return `/credentials/v1/status-lists/${encodeURIComponent(tenantId)}/revocation`;
};

export const revocationStatusListUrlForTenant = (requestUrl: string, tenantId: string): string => {
  return new URL(revocationStatusListPathForTenant(tenantId), requestUrl).toString();
};

export const credentialStatusForAssertion = (
  statusListCredentialUrl: string,
  statusListIndex: number,
): StatusListEntryReference => {
  const statusListIndexString = String(statusListIndex);

  return {
    id: `${statusListCredentialUrl}#entry-${statusListIndexString}`,
    type: 'BitstringStatusListEntry',
    statusPurpose: 'revocation',
    statusListIndex: statusListIndexString,
    statusListCredential: statusListCredentialUrl,
  };
};

export const encodeRevocationBitstring = async (
  statusEntries: readonly RevocationStatusBitEntry[],
): Promise<string> => {
  let maxStatusListIndex = -1;

  for (const entry of statusEntries) {
    if (!Number.isInteger(entry.statusListIndex) || entry.statusListIndex < 0) {
      throw new Error(`Invalid status list index "${String(entry.statusListIndex)}"`);
    }

    maxStatusListIndex = Math.max(maxStatusListIndex, entry.statusListIndex);
  }

  const bitsetLength = maxStatusListIndex < 0 ? 1 : Math.floor(maxStatusListIndex / 8) + 1;
  const bitset = new Uint8Array(bitsetLength);

  for (const entry of statusEntries) {
    if (!entry.revoked) {
      continue;
    }

    const byteIndex = Math.floor(entry.statusListIndex / 8);
    const bitIndex = entry.statusListIndex % 8;
    const currentByte = bitset[byteIndex] ?? 0;
    bitset[byteIndex] = currentByte | (1 << bitIndex);
  }

  const compressed = await gzipBytes(bitset);
  return `u${bytesToBase64Url(compressed)}`;
};

export interface BuildRevocationStatusListCredentialInput {
  requestUrl: string;
  tenantId: string;
  issuerDid: string;
  statusEntries: readonly RevocationStatusBitEntry[];
}

export const buildRevocationStatusListCredential = async (
  input: BuildRevocationStatusListCredentialInput,
): Promise<{
  credential: JsonObject;
  issuedAt: string;
}> => {
  const statusListCredentialUrl = revocationStatusListUrlForTenant(
    input.requestUrl,
    input.tenantId,
  );
  const encodedList = await encodeRevocationBitstring(input.statusEntries);
  const issuedAt = new Date().toISOString();

  return {
    issuedAt,
    credential: {
      '@context': ['https://www.w3.org/ns/credentials/v2', BITSTRING_STATUS_LIST_CONTEXT],
      id: statusListCredentialUrl,
      type: ['VerifiableCredential', 'BitstringStatusListCredential'],
      issuer: input.issuerDid,
      validFrom: issuedAt,
      credentialSubject: {
        id: `${statusListCredentialUrl}#list`,
        type: 'BitstringStatusList',
        statusPurpose: 'revocation',
        encodedList,
      },
    },
  };
};

export const parseStatusListIndex = (value: string): number | null => {
  if (!/^\d+$/.test(value)) {
    return null;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
};

export const decodedRevocationStatusBit = async (
  encodedList: string,
  statusListIndex: number,
): Promise<boolean | null> => {
  if (!encodedList.startsWith('u')) {
    return null;
  }

  const compressedBytes = base64UrlToBytes(encodedList.slice(1));

  if (compressedBytes === null) {
    return null;
  }

  const bitset = await gunzipBytes(compressedBytes);

  if (bitset === null) {
    return null;
  }

  const byteIndex = Math.floor(statusListIndex / 8);
  const bitIndex = statusListIndex % 8;

  if (byteIndex >= bitset.length) {
    return null;
  }

  const byte = bitset[byteIndex] ?? 0;
  return (byte & (1 << bitIndex)) !== 0;
};
