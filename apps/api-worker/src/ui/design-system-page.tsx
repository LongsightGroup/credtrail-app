import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "./render-page";
import {
  CtActionGroup,
  CtButton,
  CtButtonLink,
  CtTextButton,
  CtTextLink,
  type CtActionSize,
  type CtActionVariant,
} from "./actions";
import {
  CtCheckboxField,
  CtField,
  CtFieldError,
  CtFieldHint,
  CtForm,
  CtInput,
  CtSelect,
  CtTextarea,
} from "./forms";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const ACTION_VARIANTS: readonly CtActionVariant[] = ["primary", "secondary", "quiet", "danger"];
const ACTION_SIZES: readonly CtActionSize[] = ["sm", "md", "lg", "compact"];

const sentenceCase = (value: string): string => {
  return `${value.charAt(0).toUpperCase()}${value.slice(1)}`;
};

const renderActionVariantRows = (): HonoElement => {
  return (
    <div class="ct-design-system__grid">
      {ACTION_VARIANTS.map((variant) => (
        <article class="ct-design-system__example">
          <h3>{sentenceCase(variant)}</h3>
          <CtActionGroup ariaLabel={`${sentenceCase(variant)} action examples`}>
            {ACTION_SIZES.map((size) => (
              <CtButton type="button" variant={variant} size={size}>
                {sentenceCase(size)}
              </CtButton>
            ))}
          </CtActionGroup>
        </article>
      ))}
    </div>
  );
};

export const renderDesignSystemPage = (): AppPage => {
  return appPage({
    title: "Design System | CredTrail",
    assets: ["designSystemCss"],
    variant: "open",
    body: (
      <div class="ct-design-system">
        <header class="ct-design-system__header">
          <h1>Design System</h1>
          <p class="ct-design-system__section-copy">
            Shared CredTrail primitives for production app surfaces.
          </p>
        </header>
        <nav class="ct-design-system__nav" aria-label="Design system sections">
          <a href="#actions">Actions</a>
          <a href="#forms">Forms</a>
        </nav>
        <section id="actions" class="ct-design-system__section" aria-labelledby="actions-title">
          <h2 id="actions-title">Actions</h2>
          <p class="ct-design-system__section-copy">
            Buttons, link buttons, text actions, and grouped actions use one primitive contract.
          </p>
          {renderActionVariantRows()}
          <article class="ct-design-system__example">
            <h3>Links and text actions</h3>
            <CtActionGroup ariaLabel="Link and text action examples">
              <CtButtonLink href="/design-system" variant="primary" size="md">
                Open example
              </CtButtonLink>
              <CtButtonLink href="/design-system" variant="secondary" size="md">
                View details
              </CtButtonLink>
              <CtTextLink href="/design-system">Review source</CtTextLink>
              <CtTextButton type="button">Copy URL</CtTextButton>
            </CtActionGroup>
          </article>
        </section>
        <section id="forms" class="ct-design-system__section" aria-labelledby="forms-title">
          <h2 id="forms-title">Forms</h2>
          <p class="ct-design-system__section-copy">
            Fields, controls, hints, errors, and selection rows share one primitive contract.
          </p>
          <CtForm className="ct-design-system__form-grid">
            <article class="ct-design-system__example">
              <h3>Inputs and selects</h3>
              <CtField label="Required text input">
                <CtInput
                  name="exampleText"
                  type="text"
                  required
                  placeholder="Credential title"
                  describedBy="design-system-input-hint"
                />
                <CtFieldHint id="design-system-input-hint">Use a learner-facing label.</CtFieldHint>
              </CtField>
              <CtField label="Compact select" compact>
                <CtSelect name="exampleSelect">
                  <option value="">Choose status</option>
                  <option value="ready">Ready</option>
                  <option value="draft">Draft</option>
                </CtSelect>
              </CtField>
            </article>
            <article class="ct-design-system__example">
              <h3>Textarea variants</h3>
              <CtField label="Prose textarea">
                <CtTextarea
                  name="exampleProse"
                  variant="prose"
                  rows={3}
                  value="Short credential summary for public badge pages."
                />
              </CtField>
              <CtField label="Code textarea">
                <CtTextarea
                  name="exampleCode"
                  variant="code"
                  rows={3}
                  value={`{"criteria":"verified"}`}
                />
              </CtField>
            </article>
            <article class="ct-design-system__example">
              <h3>States</h3>
              <CtField label="Readonly input">
                <CtInput name="exampleReadonly" value="Generated after save" readonly />
              </CtField>
              <CtField label="Disabled input">
                <CtInput name="exampleDisabled" value="Unavailable" disabled />
              </CtField>
              <CtField label="Invalid input">
                <CtInput
                  name="exampleInvalid"
                  value="missing-at-symbol"
                  className="user-invalid-fallback"
                  describedBy={["design-system-invalid-error"]}
                />
                <CtFieldError id="design-system-invalid-error">
                  Enter a valid email address.
                </CtFieldError>
              </CtField>
            </article>
            <article class="ct-design-system__example">
              <h3>Selection rows</h3>
              <CtCheckboxField
                name="exampleCheckbox"
                value="yes"
                label="Send learner notice"
                checked
              />
              <CtCheckboxField
                name="exampleRadio"
                type="radio"
                value="now"
                label="Issue immediately"
                checked
              />
              <CtCheckboxField
                name="exampleRadio"
                type="radio"
                value="later"
                label="Save as draft"
              />
            </article>
          </CtForm>
        </section>
      </div>
    ),
  });
};
