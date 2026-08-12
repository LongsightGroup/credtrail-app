import { describe, expect, it } from "vitest";
import { badgeRuleAuthoringHttpFailure } from "./badge-rule-authoring-http";

describe("badgeRuleAuthoringHttpFailure", () => {
  it("keeps temporary artwork storage failures retryable", () => {
    expect(badgeRuleAuthoringHttpFailure("template_artwork_unavailable")).toEqual({
      error:
        "CredTrail could not check this badge's artwork right now. Wait a moment and try again.",
      statusCode: 503,
    });
  });
});
