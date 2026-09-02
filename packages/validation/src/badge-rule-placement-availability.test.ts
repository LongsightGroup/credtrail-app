import { describe, expect, it } from "vitest";

import { parseReplaceBadgeRulePlacementAvailabilityRequest } from "./badge-rule-placement-availability.js";

describe("badge rule placement availability parser", () => {
  it("parses each closed availability variant", () => {
    expect(
      parseReplaceBadgeRulePlacementAvailabilityRequest({
        scope: "selected_courses",
        courseContextIds: [" lctx_one ", "lctx_two"],
      }),
    ).toEqual({
      scope: "selected_courses",
      courseContextIds: ["lctx_one", "lctx_two"],
    });
    expect(
      parseReplaceBadgeRulePlacementAvailabilityRequest({
        scope: "org_unit_subtree",
        rootOrgUnitId: " ou_college ",
      }),
    ).toEqual({ scope: "org_unit_subtree", rootOrgUnitId: "ou_college" });
    expect(parseReplaceBadgeRulePlacementAvailabilityRequest({ scope: "tenant" })).toEqual({
      scope: "tenant",
    });
  });

  it.each([
    { scope: "selected_courses", courseContextIds: [] },
    { scope: "selected_courses", courseContextIds: ["lctx_one", "lctx_one"] },
    { scope: "selected_courses", courseContextIds: [" "] },
    { scope: "selected_courses", courseContextIds: ["lctx_one"], rootOrgUnitId: "ou_one" },
    { scope: "org_unit_subtree", rootOrgUnitId: " " },
    { scope: "org_unit_subtree", rootOrgUnitId: "ou_one", courseContextIds: ["lctx_one"] },
    { scope: "tenant", rootOrgUnitId: "ou_one" },
    { scope: "tenant", courseContextIds: ["lctx_one"] },
    { scope: "course_relative_blueprint", courseContextIds: ["lctx_one"] },
  ])("rejects invalid or contradictory input %#", (input) => {
    expect(() => parseReplaceBadgeRulePlacementAvailabilityRequest(input)).toThrow(/./);
  });
});
