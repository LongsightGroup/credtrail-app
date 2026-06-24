import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "./render-page";
import {
  CtActionGroup,
  CtButton,
  CtButtonLink,
  CtTextButton,
  type CtActionSize,
  type CtActionVariant,
} from "./actions";

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
              <CtTextButton href="/design-system">Review source</CtTextButton>
              <CtTextButton type="button">Copy URL</CtTextButton>
            </CtActionGroup>
          </article>
        </section>
      </div>
    ),
  });
};
