import { describe, expect, it } from "vitest";
import { AdminActions, AdminButton, AdminButtonLink } from "../admin/components";
import { PublicBadgeButton, PublicBadgeButtonLink } from "../badges/public-badge-ui";
import { CtActionGroup, CtButton, CtButtonLink, CtTextButton, ctActionClass } from "./actions";
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
        variant="secondary"
        size="lg"
        target="_blank"
        rel="noopener noreferrer"
        disabled={true}
        ariaLabel="Open records"
        dataAttributes={{ "data-records-link": "true" }}
      >
        Open records
      </CtButtonLink>,
    );

    expect(html).toContain('href="/records"');
    expect(html).toContain('target="_blank"');
    expect(html).toContain('rel="noopener noreferrer"');
    expect(html).toContain('aria-disabled="true"');
    expect(html).toContain('aria-label="Open records"');
    expect(html).toContain('data-records-link="true"');
    expect(html).toContain("ct-action--secondary");
    expect(html).toContain("ct-action--lg");
  });

  it("renders text actions as buttons or links", () => {
    const buttonHtml = renderToString(
      <CtTextButton id="copy-url" dataAttributes={{ "data-copy-value": "https://credtrail.org" }}>
        Copy URL
      </CtTextButton>,
    );
    const linkHtml = renderToString(
      <CtTextButton href="/source" target="_blank" rel="noopener noreferrer">
        Review source
      </CtTextButton>,
    );

    expect(buttonHtml).toContain("<button");
    expect(buttonHtml).toContain("ct-action--text");
    expect(buttonHtml).toContain('data-copy-value="https://credtrail.org"');
    expect(linkHtml).toContain("<a");
    expect(linkHtml).toContain('href="/source"');
    expect(linkHtml).toContain('target="_blank"');
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

  it("keeps admin wrappers compatible while adding primitive classes", () => {
    const buttonHtml = renderToString(
      <AdminButton type="submit" variant="danger" size="tiny" form="delete-form">
        Delete record
      </AdminButton>,
    );
    const linkHtml = renderToString(
      <AdminButtonLink href="/admin/rules" variant="ghost" size="tiny">
        View rules
      </AdminButtonLink>,
    );
    const groupHtml = renderToString(
      <AdminActions align="end">
        <AdminButton>Save changes</AdminButton>
      </AdminActions>,
    );

    expect(buttonHtml).toContain("ct-admin__button");
    expect(buttonHtml).toContain("ct-admin__button--tiny");
    expect(buttonHtml).toContain("ct-admin__button--danger");
    expect(buttonHtml).toContain("ct-action--danger");
    expect(buttonHtml).toContain("ct-action--sm");
    expect(linkHtml).toContain("ct-admin__button--ghost");
    expect(linkHtml).toContain("ct-action--quiet");
    expect(groupHtml).toContain("ct-admin__actions");
    expect(groupHtml).toContain("ct-action-group");
  });

  it("keeps public badge wrappers compatible while adding primitive classes", () => {
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
