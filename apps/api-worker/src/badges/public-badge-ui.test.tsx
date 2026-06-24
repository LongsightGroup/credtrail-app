import { describe, expect, it } from "vitest";
import { PublicBadgeButton, PublicBadgeButtonLink } from "./public-badge-ui";

const renderToString = (node: { toString(): string }): string => {
  return node.toString();
};

describe("public badge action wrappers", () => {
  it("keeps public badge wrappers compatible while delegating visual classes to primitives", () => {
    const buttonHtml = renderToString(
      <PublicBadgeButton
        id="copy-badge"
        variant="primary"
        dataCopyValue="https://credtrail.org/badges/1"
      >
        Copy badge URL
      </PublicBadgeButton>,
    );
    const linkHtml = renderToString(
      <PublicBadgeButtonLink href="/badges/1" variant="secondary">
        View badge
      </PublicBadgeButtonLink>,
    );

    expect(buttonHtml).toContain("public-badge__button--primary");
    expect(buttonHtml).toContain("ct-action--primary");
    expect(buttonHtml).toContain("ct-action--lg");
    expect(buttonHtml).toContain('data-copy-value="https://credtrail.org/badges/1"');
    expect(linkHtml).toContain("public-badge__button");
    expect(linkHtml).toContain("ct-action--secondary");
  });
});
