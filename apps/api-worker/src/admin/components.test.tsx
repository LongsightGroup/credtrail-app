import { describe, expect, it } from "vitest";
import { AdminActions, AdminButton, AdminButtonLink } from "./actions";

const renderToString = (node: { toString(): string }): string => {
  return node.toString();
};

describe("admin action wrappers", () => {
  it("keeps admin wrappers compatible while delegating visual classes to primitives", () => {
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
    expect(buttonHtml).not.toContain("ct-admin__button--");
    expect(buttonHtml).toContain("ct-action--danger");
    expect(buttonHtml).toContain("ct-action--sm");
    expect(linkHtml).toContain("ct-admin__button");
    expect(linkHtml).not.toContain("ct-admin__button--");
    expect(linkHtml).toContain("ct-action--quiet");
    expect(groupHtml).toContain("ct-admin__actions--end");
    expect(groupHtml).toContain("ct-action-group");
  });
});
