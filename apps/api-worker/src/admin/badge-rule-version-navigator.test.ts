import { describe, expect, it } from "vitest";
import {
  sampleDetailRule,
  sampleDetailVersion,
} from "../institution-admin-test-utils/rule-version-fixtures";
import { buildBadgeRuleVersionNavigationModel } from "./badge-rule-version-navigator";

describe("badge rule version navigation model", () => {
  it("derives adjacent versions from canonical order, not caller order", () => {
    const firstVersion = sampleDetailVersion("brv_first", 1, "active");
    const selectedVersion = sampleDetailVersion("brv_selected", 2, "rejected");
    const latestVersion = sampleDetailVersion("brv_latest", 3, "draft");

    const navigation = buildBadgeRuleVersionNavigationModel({
      rule: sampleDetailRule(firstVersion.id),
      selectedVersion,
      versions: [firstVersion, latestVersion, selectedVersion],
    });

    expect(navigation.orderedVersions.map((version) => version.id)).toEqual([
      latestVersion.id,
      selectedVersion.id,
      firstVersion.id,
    ]);
    expect(navigation.latestVersion.id).toBe(latestVersion.id);
    expect(navigation.previousVersion?.id).toBe(firstVersion.id);
    expect(navigation.nextVersion?.id).toBe(latestVersion.id);
  });
});
