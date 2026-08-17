/** A resolved IP address considered for an outbound verifier request. */
export interface ResolvedNetworkAddress {
  readonly address: string;
  readonly family: 4 | 6;
}

/** Normalizes URL and DNS hostname forms before applying outbound-network policy. */
export const normalizeNetworkHostname = (hostname: string): string => {
  const withoutIpv6Brackets =
    hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  return withoutIpv6Brackets.toLowerCase().replace(/\.$/u, "");
};

const parseIpv4Address = (value: string): readonly [number, number, number, number] | null => {
  const parts = value.split(".");

  if (parts.length !== 4) {
    return null;
  }

  const octets: number[] = [];

  for (const part of parts) {
    if (!/^\d{1,3}$/u.test(part)) {
      return null;
    }

    const octet = Number(part);

    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      return null;
    }

    octets.push(octet);
  }

  const [first, second, third, fourth] = octets;
  return first === undefined || second === undefined || third === undefined || fourth === undefined
    ? null
    : [first, second, third, fourth];
};

const ipv4Words = (value: string): readonly [number, number] | null => {
  const octets = parseIpv4Address(value);

  if (octets === null) {
    return null;
  }

  return [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]];
};

const parseIpv6Side = (side: string): number[] | null => {
  if (side.length === 0) {
    return [];
  }

  const tokens = side.split(":");
  const words: number[] = [];

  for (const [index, token] of tokens.entries()) {
    const embeddedIpv4 = ipv4Words(token);

    if (embeddedIpv4 !== null) {
      if (index !== tokens.length - 1) {
        return null;
      }

      words.push(...embeddedIpv4);
      continue;
    }

    if (!/^[\da-f]{1,4}$/iu.test(token)) {
      return null;
    }

    words.push(Number.parseInt(token, 16));
  }

  return words;
};

const parseIpv6Address = (value: string): readonly number[] | null => {
  if (value.includes("%") || value.split("::").length > 2) {
    return null;
  }

  const [leftText = "", rightText] = value.split("::");
  const left = parseIpv6Side(leftText);
  const right = rightText === undefined ? [] : parseIpv6Side(rightText);

  if (left === null || right === null) {
    return null;
  }

  if (rightText === undefined) {
    return left.length === 8 ? left : null;
  }

  const missingWordCount = 8 - left.length - right.length;

  if (missingWordCount < 1) {
    return null;
  }

  return [...left, ...Array.from({ length: missingWordCount }, () => 0), ...right];
};

const isPublicIpv4 = (octets: readonly [number, number, number, number]): boolean => {
  const [first, second, third] = octets;

  return !(
    first === 0 ||
    first === 10 ||
    first === 127 ||
    first >= 224 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 0 && third === 0) ||
    (first === 192 && second === 0 && third === 2) ||
    (first === 192 && second === 88 && third === 99) ||
    (first === 192 && second === 168) ||
    (first === 198 && (second === 18 || second === 19)) ||
    (first === 198 && second === 51 && third === 100) ||
    (first === 203 && second === 0 && third === 113)
  );
};

const isPublicIpv6 = (words: readonly number[]): boolean => {
  const [first = 0, second = 0, third = 0, fourth = 0, fifth = 0, sixth = 0] = words;
  const isIpv4Mapped =
    first === 0 && second === 0 && third === 0 && fourth === 0 && fifth === 0 && sixth === 0xffff;

  if (isIpv4Mapped) {
    const high = words[6] ?? 0;
    const low = words[7] ?? 0;
    return isPublicIpv4([high >> 8, high & 0xff, low >> 8, low & 0xff]);
  }

  const isGlobalUnicast = first >= 0x2000 && first <= 0x3fff;

  if (!isGlobalUnicast) {
    return false;
  }

  return !(
    (first === 0x2001 && second === 0x0db8) ||
    (first === 0x2001 && second <= 0x01ff) ||
    first === 0x2002
  );
};

const networkAddressFamily = (address: string): 4 | 6 | null => {
  if (parseIpv4Address(address) !== null) {
    return 4;
  }

  return parseIpv6Address(address) === null ? null : 6;
};

/** Returns whether a resolved address is globally routable public unicast. */
export const isPublicNetworkAddress = (address: ResolvedNetworkAddress): boolean => {
  const normalized = normalizeNetworkHostname(address.address);

  if (address.family === 4) {
    const parsed = parseIpv4Address(normalized);
    return parsed !== null && isPublicIpv4(parsed);
  }

  const parsed = parseIpv6Address(normalized);
  return parsed !== null && isPublicIpv6(parsed);
};

/** Parses a URL hostname when it is an IP literal. */
export const literalNetworkAddress = (hostname: string): ResolvedNetworkAddress | null => {
  const normalized = normalizeNetworkHostname(hostname);
  const family = networkAddressFamily(normalized);
  return family === null ? null : { address: normalized, family };
};

/** Rejects hostnames reserved for loopback, link-local, and internal naming. */
export const isBlockedNetworkHostname = (hostname: string): boolean => {
  const normalized = normalizeNetworkHostname(hostname);
  return (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    normalized.endsWith(".local") ||
    normalized.endsWith(".internal") ||
    normalized.endsWith(".lan") ||
    normalized.endsWith(".home.arpa")
  );
};
