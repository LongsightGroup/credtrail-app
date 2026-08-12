import {
  badgeAchievementSnapshotSchema,
  type BadgeAchievementSnapshot,
} from "@credtrail/validation";

/** Parses the immutable achievement snapshot stored with one assertion. */
export const parseStoredAssertionAchievementSnapshot = (
  snapshotJson: string,
): BadgeAchievementSnapshot => {
  const parsedJson: unknown = JSON.parse(snapshotJson);
  return badgeAchievementSnapshotSchema.parse(parsedJson);
};

/** Serializes a parsed achievement snapshot for assertion persistence. */
export const serializeAssertionAchievementSnapshot = (
  snapshot: BadgeAchievementSnapshot,
): string => {
  return JSON.stringify(badgeAchievementSnapshotSchema.parse(snapshot));
};
