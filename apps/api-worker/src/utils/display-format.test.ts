import { describe, expect, it } from "vitest";
import { linkedinOrganizationIdSchema } from "@credtrail/validation";
import { linkedInAddToProfileUrl } from "./display-format";
const input = {
  badgeName: "Research & Practice",
  issuerName: "Example University",
  issuedAtIso: "2026-01-31T23:30:00-02:00",
  credentialUrl: "https://credtrail.org/badges/example",
  credentialId: "urn:credential:123",
};
describe("LinkedIn profile link", () => {
  it("uses the organization ID with exact digits and preserves the credential and UTC issue date", () => {
    const url = new URL(
      linkedInAddToProfileUrl({
        ...input,
        organizationId: linkedinOrganizationIdSchema.parse("90071992547409931234"),
      }),
    );
    expect(url.origin + url.pathname).toBe("https://www.linkedin.com/profile/add");
    expect(Object.fromEntries(url.searchParams)).toEqual({
      startTask: "CERTIFICATION_NAME",
      name: input.badgeName,
      certUrl: input.credentialUrl,
      certId: input.credentialId,
      organizationId: "90071992547409931234",
      issueYear: "2026",
      issueMonth: "2",
    });
  });
  it("adds the expiration date when the credential has one, and omits it otherwise", () => {
    const withExpiry = new URL(
      linkedInAddToProfileUrl({
        ...input,
        organizationId: null,
        validUntilIso: "2027-12-31T23:59:59.000Z",
      }),
    ).searchParams;
    expect(withExpiry.get("expirationYear")).toBe("2027");
    expect(withExpiry.get("expirationMonth")).toBe("12");
    const withoutExpiry = new URL(
      linkedInAddToProfileUrl({ ...input, organizationId: null, validUntilIso: null }),
    ).searchParams;
    expect(withoutExpiry.has("expirationYear")).toBe(false);
    expect(withoutExpiry.has("expirationMonth")).toBe(false);
  });

  it("uses the issuer name when unconfigured", () => {
    const params = new URL(linkedInAddToProfileUrl({ ...input, organizationId: null }))
      .searchParams;
    expect(params.get("organizationName")).toBe(input.issuerName);
    expect(params.has("organizationId")).toBe(false);
  });
  it("omits absent issuer, credential ID and invalid date", () => {
    const params = new URL(
      linkedInAddToProfileUrl({
        ...input,
        organizationId: null,
        issuerName: "Unknown issuer",
        credentialId: " ",
        issuedAtIso: "invalid",
      }),
    ).searchParams;
    for (const key of ["organizationName", "organizationId", "certId", "issueYear", "issueMonth"])
      expect(params.has(key)).toBe(false);
  });
});
