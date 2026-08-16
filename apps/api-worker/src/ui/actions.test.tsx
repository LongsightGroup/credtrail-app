import { describe, expect, it } from "vitest";
import {
  CtActionGroup,
  CtButton,
  CtButtonLink,
  CtTextButton,
  CtTextLink,
  ctActionClass,
} from "./actions";
import { renderDesignSystemPage } from "./design-system-page";
import { renderAppPageToString } from "./render-page";

const renderToString = (node: { toString(): string }): string => {
  return node.toString();
};

describe("CredTrail action primitives", () => {
  it("builds action classes from variants and sizes", () => {
    expect(ctActionClass()).toBe("ct-action ct-action--primary ct-action--md");
    expect(
      ctActionClass({
        variant: "danger",
        size: "compact",
        className: "custom-action",
      }),
    ).toBe("custom-action ct-action ct-action--danger ct-action--compact");
    expect(ctActionClass({ text: true })).toBe(
      "ct-action ct-action--primary ct-action--md ct-action--text",
    );
  });

  it("renders real buttons with expected attributes", () => {
    const html = renderToString(
      <CtButton
        id="approve-action"
        type="submit"
        variant="danger"
        size="sm"
        disabled={true}
        hidden={true}
        form="approval-form"
        formAction="/approve"
        name="decision"
        value="approve"
        ariaLabel="Approve badge"
        ariaControls="approval-panel"
        ariaExpanded={true}
        dataAttributes={{ "data-action": "approve" }}
      >
        Approve
      </CtButton>,
    );

    expect(html).toContain('id="approve-action"');
    expect(html).toContain('type="submit"');
    expect(html).toContain('form="approval-form"');
    expect(html).toContain('formaction="/approve"');
    expect(html).toContain('name="decision"');
    expect(html).toContain('value="approve"');
    expect(html).toContain('aria-label="Approve badge"');
    expect(html).toContain('aria-controls="approval-panel"');
    expect(html).toContain('aria-expanded="true"');
    expect(html).toContain('data-action="approve"');
    expect(html).toContain("disabled");
    expect(html).toContain("hidden");
    expect(html).toContain("ct-action--danger");
    expect(html).toContain("ct-action--sm");
  });

  it("renders link buttons with link-specific attributes", () => {
    const html = renderToString(
      <CtButtonLink
        href="/records"
        variant="primary"
        size="sm"
        target="_blank"
        rel="noopener noreferrer"
        ariaLabel="Open records"
        dataAttributes={{ "data-records-link": "true" }}
      >
        Open records
      </CtButtonLink>,
    );

    expect(html).toContain('href="/records"');
    expect(html).toContain('target="_blank"');
    expect(html).toContain('rel="noopener noreferrer"');
    expect(html).toContain('aria-label="Open records"');
    expect(html).toContain('data-records-link="true"');
    expect(html).toContain('class="ct-action ct-action--primary ct-action--sm"');
    expect(html).not.toContain("ct-admin__button");
  });

  it("renders text button actions as buttons", () => {
    const html = renderToString(
      <CtTextButton id="copy-url" dataAttributes={{ "data-copy-value": "https://credtrail.org" }}>
        Copy URL
      </CtTextButton>,
    );

    expect(html).toContain("<button");
    expect(html).toContain("ct-action--text");
    expect(html).toContain('data-copy-value="https://credtrail.org"');
  });

  it("renders text link actions as links", () => {
    const html = renderToString(
      <CtTextLink href="/source" target="_blank" rel="noopener noreferrer">
        Review source
      </CtTextLink>,
    );

    expect(html).toContain("<a");
    expect(html).toContain("ct-action--text");
    expect(html).toContain('href="/source"');
    expect(html).toContain('target="_blank"');
  });

  it("renders labeled action groups as accessible groups", () => {
    const html = renderToString(
      <CtActionGroup ariaLabel="Record actions">
        <CtButton>Save changes</CtButton>
      </CtActionGroup>,
    );

    expect(html).toContain('class="ct-action-group"');
    expect(html).toContain('role="group"');
    expect(html).toContain('aria-label="Record actions"');
  });

  it("renders the design-system action gallery", () => {
    const html = renderAppPageToString(renderDesignSystemPage());

    expect(html).toContain("Design System | CredTrail");
    expect(html).toContain('id="actions"');
    expect(html).toContain('aria-label="Primary action examples"');
    expect(html).toContain("ct-action--primary");
    expect(html).toContain("ct-action--secondary");
    expect(html).toContain("ct-action--quiet");
    expect(html).toContain("ct-action--danger");
    expect(html).toContain("ct-action--compact");
    expect(html).toContain("ct-action--text");
  });
});
