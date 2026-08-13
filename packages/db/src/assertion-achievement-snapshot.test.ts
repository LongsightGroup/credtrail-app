import { describe, expect, it } from "vitest";

import { resolveStoredAssertionAchievement } from "./assertion-achievement-snapshot";

const currentTemplate = {
  badgeTemplateId: "template_123",
} as const;

describe("resolveStoredAssertionAchievement", () => {
  it("returns a captured immutable issuance snapshot", () => {
    const capturedSnapshot = {
      badgeTemplateId: "template_123",
      title: "Title at issuance",
      description: "Description at issuance",
      criteriaUri: "https://example.edu/criteria/issuance",
      imageUri: "https://example.edu/badges/issuance.png",
      trustedCredentialMetadataJson: null,
    };

    const resolved = resolveStoredAssertionAchievement({
      ...currentTemplate,
      achievementSnapshotStatus: "captured",
      achievementSnapshotJson: JSON.stringify(capturedSnapshot),
    });

    expect(resolved).toEqual({ status: "captured", snapshot: capturedSnapshot });
  });

  it("does not invent achievement details for preserved assertions", () => {
    const resolved = resolveStoredAssertionAchievement({
      ...currentTemplate,
      achievementSnapshotStatus: "unavailable",
      achievementSnapshotJson: null,
    });

    expect(resolved).toEqual({
      status: "unavailable",
      snapshot: {
        badgeTemplateId: "template_123",
        title: "Achievement snapshot unavailable",
        description:
          "The signed credential is preserved, but its issuance-time achievement snapshot was not recorded.",
        criteriaUri: null,
        imageUri: null,
        trustedCredentialMetadataJson: null,
      },
    });
  });

  it("rejects contradictory persisted snapshot state", () => {
    expect(() =>
      resolveStoredAssertionAchievement({
        ...currentTemplate,
        achievementSnapshotStatus: "captured",
        achievementSnapshotJson: null,
      }),
    ).toThrow("Captured assertion achievement snapshot is missing");
  });
});
