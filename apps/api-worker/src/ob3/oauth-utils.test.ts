import { describe, expect, it } from "vitest";
import {
  parseCompactJwsHeaderObject,
  parseCompactJwsPayloadObject,
  resolveOb3CredentialIdFromCompactJws,
} from "./oauth-utils";

const bytesToBase64UrlForTest = (bytes: Uint8Array): string => {
  let raw = "";

  for (const byte of bytes) {
    raw += String.fromCharCode(byte);
  }

  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

describe("compact JWS parsing", () => {
  it("decodes OB3 credential compact JWS header and payload through the jose wrapper", () => {
    const compactJws =
      "eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuZWR1L2tleXMja2V5LTEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmVkdSIsImp0aSI6InVybjpjcmVkdHJhaWw6Y3JlZGVudGlhbDpqd3MiLCJuYmYiOjE3NjI4OTQ4MDAsInN1YiI6Im1haWx0bzpsZWFybmVyQGV4YW1wbGUuZWR1In0.signature";

    expect(parseCompactJwsHeaderObject(compactJws)).toEqual({
      alg: "RS256",
      kid: "https://issuer.example.edu/keys#key-1",
      typ: "JWT",
    });
    expect(parseCompactJwsPayloadObject(compactJws)).toEqual({
      iss: "https://issuer.example.edu",
      jti: "urn:credtrail:credential:jws",
      nbf: 1762894800,
      sub: "mailto:learner@example.edu",
    });
    expect(resolveOb3CredentialIdFromCompactJws(compactJws)).toBe("urn:credtrail:credential:jws");
  });

  it("rejects detached or unencoded payload compact JWS forms", () => {
    const unencodedHeader = bytesToBase64UrlForTest(
      new TextEncoder().encode(JSON.stringify({ alg: "RS256", b64: false, crit: ["b64"] })),
    );

    expect(parseCompactJwsPayloadObject(`${unencodedHeader}.raw-payload.signature`)).toBeNull();
    expect(parseCompactJwsPayloadObject(`${unencodedHeader}..signature`)).toBeNull();
  });

  it("rejects malformed compact JWS input instead of partially decoding segments", () => {
    expect(parseCompactJwsHeaderObject("not-a-jws")).toBeNull();
    expect(parseCompactJwsPayloadObject("a.b.c.d")).toBeNull();
    expect(() => resolveOb3CredentialIdFromCompactJws("not-a-jws")).toThrow(
      "Compact JWS must contain JSON JOSE header and payload objects",
    );
  });
});
