import { describe, expect, it } from "vitest";
import { AdminActions, AdminButton, AdminButtonLink } from "./actions";
import { AdminCheckboxRow, AdminField, AdminForm } from "./components";
import { CtInput } from "../ui/forms";

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

describe("admin form wrappers", () => {
  it("keeps admin wrapper classes while delegating to form primitives", () => {
    const formHtml = renderToString(
      <AdminForm id="admin-form" method="post" action="/admin/save">
        <AdminField label="Title">
          <CtInput name="title" type="text" />
        </AdminField>
        <AdminCheckboxRow name="enabled" value="1" label="Enabled" />
      </AdminForm>,
    );

    expect(formHtml).toContain("ct-admin__form ct-stack ct-form");
    expect(formHtml).toContain("ct-admin__field ct-field");
    expect(formHtml).toContain("ct-field__label");
    expect(formHtml).toContain("ct-admin__checkbox-row ct-checkbox-field");
    expect(formHtml).toContain('name="enabled"');
    expect(formHtml).toContain('type="checkbox"');
  });
});
