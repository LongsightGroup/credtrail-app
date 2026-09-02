import { describe, expect, it } from "vitest";
import { parseGovernanceMetadataJson } from "./governance-metadata.js";

describe("governance metadata", () => {
  it("parses JSON objects without imposing feature-specific policy", () => {
    expect(
      parseGovernanceMetadataJson(
        JSON.stringify({ stability: "institution_registry", approval: "registrar" }),
      ),
    ).toEqual({ stability: "institution_registry", approval: "registrar" });
    expect(parseGovernanceMetadataJson(null)).toBeNull();
  });

  it("rejects invalid JSON and non-object values", () => {
    expect(parseGovernanceMetadataJson("{not-json")).toBeNull();
    expect(parseGovernanceMetadataJson("[]")).toBeNull();
    expect(parseGovernanceMetadataJson("null")).toBeNull();
  });
});
