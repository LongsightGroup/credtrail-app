import {
  badgeAchievementSnapshotSchema,
  type BadgeAchievementSnapshot,
} from "@credtrail/validation";

export type AssertionAchievementSnapshotStatus = "captured" | "unavailable";

export interface StoredAssertionAchievementInput {
  readonly badgeTemplateId: string;
  readonly achievementSnapshotJson: string | null;
  readonly achievementSnapshotStatus: string;
}

export interface StoredAssertionAchievement {
  readonly snapshot: BadgeAchievementSnapshot;
  readonly status: AssertionAchievementSnapshotStatus;
}

/** Parses the immutable achievement snapshot stored with one assertion. */
export const parseStoredAssertionAchievementSnapshot = (
  snapshotJson: string,
): BadgeAchievementSnapshot => {
  const parsedJson: unknown = JSON.parse(snapshotJson);
  return badgeAchievementSnapshotSchema.parse(parsedJson);
};

/**
 * Parses a captured issuance snapshot or returns an explicit unavailable
 * projection without inventing historical achievement details.
 */
export const resolveStoredAssertionAchievement = (
  input: StoredAssertionAchievementInput,
): StoredAssertionAchievement => {
  if (input.achievementSnapshotStatus === "captured") {
    if (input.achievementSnapshotJson === null) {
      throw new Error("Captured assertion achievement snapshot is missing");
    }

    const snapshot = parseStoredAssertionAchievementSnapshot(input.achievementSnapshotJson);

    if (snapshot.badgeTemplateId !== input.badgeTemplateId) {
      throw new Error("Assertion achievement snapshot badge template does not match");
    }

    return { snapshot, status: "captured" };
  }

  if (input.achievementSnapshotStatus === "unavailable") {
    if (input.achievementSnapshotJson !== null) {
      throw new Error("Unavailable assertion achievement snapshot contains captured data");
    }

    return {
      snapshot: badgeAchievementSnapshotSchema.parse({
        badgeTemplateId: input.badgeTemplateId,
        title: "Achievement snapshot unavailable",
        description:
          "The signed credential is preserved, but its issuance-time achievement snapshot was not recorded.",
        criteriaUri: null,
        imageUri: null,
        trustedCredentialMetadataJson: null,
      }),
      status: "unavailable",
    };
  }

  throw new Error("Unknown assertion achievement snapshot status");
};

/** Serializes a parsed achievement snapshot for assertion persistence. */
export const serializeAssertionAchievementSnapshot = (
  snapshot: BadgeAchievementSnapshot,
): string => {
  return JSON.stringify(badgeAchievementSnapshotSchema.parse(snapshot));
};
