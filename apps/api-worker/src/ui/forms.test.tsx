import { describe, expect, it } from "vitest";
import {
  CtCheckboxControl,
  CtCheckboxField,
  CtField,
  CtFieldError,
  CtFieldHint,
  CtForm,
  CtInput,
  CtSelect,
  CtTextarea,
} from "./forms";
import { renderDesignSystemPage } from "./design-system-page";
import { renderAppPageToString } from "./render-page";

const renderToString = (node: { toString(): string }): string => {
  return node.toString();
};

describe("CredTrail form primitives", () => {
  it("renders form and field primitive classes", () => {
    const html = renderToString(
      <CtForm id="credential-form" method="post" className="custom-form">
        <CtField label="Credential title" className="custom-field" compact>
          <CtInput name="title" />
        </CtField>
      </CtForm>,
    );

    expect(html).toContain('id="credential-form"');
    expect(html).toContain('method="post"');
    expect(html).toContain("custom-form ct-form");
    expect(html).toContain("custom-field ct-field ct-field--compact");
    expect(html).toContain("ct-field__label");
    expect(html).toContain("ct-input ct-field__control");
  });

  it("passes supported input attributes and typed data attributes through", () => {
    const html = renderToString(
      <CtInput
        id="email"
        name="email"
        type="email"
        value="learner@example.edu"
        placeholder="name@example.edu"
        required
        disabled
        readonly
        hidden
        autocomplete="email"
        minlength={3}
        maxlength={200}
        pattern=".+@example\\.edu"
        form="profile-form"
        ariaLabel="Institution email"
        describedBy={["email-hint", "email-error"]}
        dataAttributes={{ "data-field": "email" }}
      />,
    );

    expect(html).toContain('id="email"');
    expect(html).toContain('name="email"');
    expect(html).toContain('type="email"');
    expect(html).toContain('value="learner@example.edu"');
    expect(html).toContain('placeholder="name@example.edu"');
    expect(html).toContain('autocomplete="email"');
    expect(html).toContain('minlength="3"');
    expect(html).toContain('maxlength="200"');
    expect(html).toContain('pattern=".+@example\\\\.edu"');
    expect(html).toContain('form="profile-form"');
    expect(html).toContain('aria-label="Institution email"');
    expect(html).toContain('aria-describedby="email-hint email-error"');
    expect(html).toContain('data-field="email"');
    expect(html).toContain("required");
    expect(html).toContain("disabled");
    expect(html).toContain("readonly");
    expect(html).toContain("hidden");
  });

  it("renders hints, errors, and labeled described-by controls", () => {
    const html = renderToString(
      <CtField label="Issuer URL">
        <CtInput id="issuer-url" name="issuerUrl" type="url" />
        <CtFieldHint>Use HTTPS.</CtFieldHint>
        <CtFieldError>Enter a URL.</CtFieldError>
      </CtField>,
    );

    expect(html).toContain('<span class="ct-field__label">Issuer URL</span>');
    expect(html).toContain("Use HTTPS.");
    expect(html).toContain("ct-field__hint");
    expect(html).toContain("Enter a URL.");
    expect(html).toContain("ct-field__error");
  });

  it("renders select and textarea variant classes", () => {
    const selectHtml = renderToString(
      <CtSelect name="status" multiple size={3} dataAttributes={{ "data-status-select": "true" }}>
        <option value="active" selected>
          Active
        </option>
      </CtSelect>,
    );
    const proseHtml = renderToString(<CtTextarea name="summary" variant="prose" value="Summary" />);
    const codeHtml = renderToString(<CtTextarea name="payload" variant="code" value="{}" />);

    expect(selectHtml).toContain("<select");
    expect(selectHtml).toContain("ct-select ct-field__control");
    expect(selectHtml).toContain("multiple");
    expect(selectHtml).toContain('size="3"');
    expect(selectHtml).toContain('data-status-select="true"');
    expect(selectHtml).toContain("selected");
    expect(proseHtml).toContain("ct-textarea--prose");
    expect(codeHtml).toContain("ct-textarea--code");
  });

  it("renders checkbox and radio rows with submitted names and values", () => {
    const checkboxHtml = renderToString(
      <CtCheckboxField name="notify" value="yes" label="Notify learner" checked />,
    );
    const radioHtml = renderToString(
      <CtCheckboxField name="mode" type="radio" value="draft" label="Save draft" />,
    );
    const controlHtml = renderToString(
      <CtCheckboxControl name="learner_user_id" value="learner-001" ariaLabel="Select learner" />,
    );

    expect(checkboxHtml).toContain("ct-checkbox-field");
    expect(checkboxHtml).toContain('name="notify"');
    expect(checkboxHtml).toContain('type="checkbox"');
    expect(checkboxHtml).toContain('value="yes"');
    expect(checkboxHtml).toContain("checked");
    expect(radioHtml).toContain('name="mode"');
    expect(radioHtml).toContain('type="radio"');
    expect(radioHtml).toContain('value="draft"');
    expect(controlHtml).toContain('name="learner_user_id"');
    expect(controlHtml).toContain('type="checkbox"');
    expect(controlHtml).toContain('aria-label="Select learner"');
    expect(controlHtml).toContain("ct-checkbox-field__control");
    expect(controlHtml).not.toContain('class="ct-checkbox-field"');
  });

  it("renders standalone hint and error helpers", () => {
    const html = renderToString(
      <>
        <CtFieldHint id="hint-id">Helpful context</CtFieldHint>
        <CtFieldError id="error-id">Fix this value</CtFieldError>
      </>,
    );

    expect(html).toContain('id="hint-id"');
    expect(html).toContain("ct-field__hint");
    expect(html).toContain('id="error-id"');
    expect(html).toContain("ct-field__error");
  });

  it("wires described-by between field hints and controls", () => {
    const html = renderToString(
      <CtField label="Institution email">
        <CtInput
          id="institution-email"
          name="email"
          type="email"
          describedBy="institution-email-hint"
        />
        <CtFieldHint id="institution-email-hint">Use your work email.</CtFieldHint>
      </CtField>,
    );

    expect(html).toContain('aria-describedby="institution-email-hint"');
    expect(html).toContain('id="institution-email-hint"');
    expect(html).toContain("Use your work email.");
  });

  it("renders the design-system form gallery", () => {
    const html = renderAppPageToString(renderDesignSystemPage());

    expect(html).toContain('id="forms"');
    expect(html).toContain("ct-design-system__form-grid");
    expect(html).toContain("ct-input");
    expect(html).toContain("ct-select");
    expect(html).toContain("ct-textarea--prose");
    expect(html).toContain("ct-textarea--code");
    expect(html).toContain("ct-checkbox-field");
    expect(html).toContain("ct-field__error");
  });
});
