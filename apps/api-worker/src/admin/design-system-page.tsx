import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface ColorToken {
  name: string;
  variable: string;
  swatch: string;
  usage: string;
}

interface CodeToken {
  label: string;
  value: string;
}

const colorTokens: readonly ColorToken[] = [
  {
    name: "Midnight 900",
    variable: "--ct-brand-midnight-900",
    swatch: "midnight-900",
    usage: "Primary brand depth and filled action gradient start.",
  },
  {
    name: "Lake 700",
    variable: "--ct-brand-lake-700",
    swatch: "lake-700",
    usage: "Primary brand action and link color.",
  },
  {
    name: "Lake 500",
    variable: "--ct-brand-lake-500",
    swatch: "lake-500",
    usage: "Measured accent for gradients and charts.",
  },
  {
    name: "Sun 400",
    variable: "--ct-brand-sun-400",
    swatch: "sun-400",
    usage: "Prestige accent, not a routine call-to-action color.",
  },
  {
    name: "Mint 600",
    variable: "--ct-brand-mint-600",
    swatch: "mint-600",
    usage: "Success and active state.",
  },
  {
    name: "Amber 600",
    variable: "--ct-brand-amber-600",
    swatch: "amber-600",
    usage: "Warning and pending state.",
  },
  {
    name: "Rose 600",
    variable: "--ct-brand-rose-600",
    swatch: "rose-600",
    usage: "Danger and destructive state.",
  },
  {
    name: "Surface Info",
    variable: "--ct-theme-surface-info",
    swatch: "surface-info",
    usage: "Secondary action fill and low-emphasis callouts.",
  },
];

const approvedActionClasses: readonly CodeToken[] = [
  {
    label: "Primary action",
    value: "ct-admin__button",
  },
  {
    label: "Secondary action",
    value: "ct-admin__button ct-admin__button--secondary",
  },
  {
    label: "Tiny table action",
    value: "ct-admin__button ct-admin__button--tiny",
  },
  {
    label: "Danger action",
    value: "ct-admin__button ct-admin__button--danger",
  },
  {
    label: "Major link row item",
    value: "ct-admin__cta-link",
  },
  {
    label: "Table action group",
    value: "ct-admin__action-bar",
  },
];

const ColorTokenCard = (input: { token: ColorToken }): HonoElement => {
  return (
    <article class="ct-design-system__token">
      <div class="ct-design-system__token-head">
        <span class="ct-design-system__swatch" data-swatch={input.token.swatch}></span>
        <div>
          <h3>{input.token.name}</h3>
          <p class="ct-design-system__token-var">{input.token.variable}</p>
        </div>
      </div>
      <p class="ct-design-system__meta-text">{input.token.usage}</p>
    </article>
  );
};

const ApprovedClasses = (): HonoElement => {
  return (
    <ul class="ct-design-system__code-list">
      {approvedActionClasses.map((item) => (
        <li>
          <span class="ct-design-system__meta-text">{item.label}</span>
          <code>{item.value}</code>
        </li>
      ))}
    </ul>
  );
};

const ActionPreview = (): HonoElement => {
  return (
    <div class="ct-design-system__example-row">
      <a class="ct-admin__button" href="#actions">
        Primary
      </a>
      <button type="button" class="ct-admin__button ct-admin__button--secondary">
        Secondary
      </button>
      <button type="button" class="ct-admin__button ct-admin__button--ghost">
        Tertiary
      </button>
      <button type="button" class="ct-admin__button ct-admin__button--danger">
        Danger
      </button>
      <button type="button" class="ct-admin__button" disabled>
        Working
      </button>
    </div>
  );
};

const MajorLinkPreview = (): HonoElement => {
  return (
    <div class="ct-design-system__example-row">
      <a class="ct-admin__cta-link" href="#actions">
        Rule library and templates
      </a>
      <a class="ct-admin__cta-link" href="#actions">
        Review queue
      </a>
      <a class="ct-admin__cta-link" href="#actions">
        Download CSV template
      </a>
    </div>
  );
};

const TableActionPreview = (): HonoElement => {
  return (
    <div class="ct-design-system__action-demo">
      <div class="ct-admin__action-bar" role="group" aria-label="Example issued badge actions">
        <a class="ct-admin__button ct-admin__button--tiny" href="#actions">
          Open
        </a>
        <button
          type="button"
          class="ct-admin__button ct-admin__button--tiny ct-admin__button--secondary"
        >
          Audit
        </button>
        <details class="ct-admin__action-menu">
          <summary
            class="ct-admin__button ct-admin__button--tiny ct-admin__button--secondary ct-admin__action-menu-trigger"
            aria-label="More example actions"
          >
            ...
          </summary>
          <div class="ct-admin__action-menu-popover">
            <a class="ct-admin__action-menu-item" href="#actions">
              Open JSON-LD
            </a>
            <button
              type="button"
              class="ct-admin__action-menu-item ct-admin__action-menu-item--danger"
            >
              Revoke badge
            </button>
          </div>
        </details>
      </div>
    </div>
  );
};

const DataPreview = (): HonoElement => {
  return (
    <div class="ct-design-system__table-demo">
      <table class="ct-admin__table">
        <thead>
          <tr>
            <th>Issued</th>
            <th>Recipient</th>
            <th>State</th>
            <th>Assertion</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>5/8/2026</td>
            <td>
              <span class="ct-admin__member-identity">ern@umich.edu</span>
              <span class="ct-admin__meta">Sakai roster import</span>
            </td>
            <td>
              <span class="ct-admin__status-pill ct-admin__status-pill--active">active</span>
            </td>
            <td>
              <span class="ct-admin__assertion-id">sakai:1df79bc6-6a08-42a2</span>
            </td>
            <td class="ct-admin__issued-actions-cell">
              <div class="ct-admin__issued-actions">
                <TableActionPreview />
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  );
};

export const designSystemAdminPage = (): AppPage => {
  return appPage({
    title: "Design System | CredTrail",
    variant: "admin",
    assets: ["institutionAdminCss", "designSystemCss"],
    body: (
      <section class="ct-design-system">
        <header class="ct-admin-page-header ct-design-system__header">
          <h1>CredTrail UI Styleguide</h1>
          <p>
            Internal catalog for the current token source, admin typography, button hierarchy,
            secondary link rows, and table actions.
          </p>
        </header>

        <nav class="ct-design-system__nav" aria-label="Styleguide sections">
          <a href="#foundations">Foundations</a>
          <a href="#colors">Colors</a>
          <a href="#actions">Actions</a>
          <a href="#data">Data rows</a>
          <a href="#classes">Approved classes</a>
        </nav>

        <section class="ct-design-system__section" id="foundations">
          <h2>Foundations</h2>
          <p class="ct-design-system__section-copy">
            Newsreader carries page and section authority. Space Grotesk carries operational
            interface text, tables, forms, navigation, and controls.
          </p>
          <div class="ct-design-system__grid">
            <article class="ct-design-system__specimen">
              <h3>Display</h3>
              <p class="ct-design-system__display-text">Verified academic records</p>
              <p class="ct-design-system__token-var">--ct-font-display</p>
            </article>
            <article class="ct-design-system__specimen">
              <h3>Interface</h3>
              <p class="ct-design-system__body-text">
                Operational views stay compact, direct, and legible for administrators.
              </p>
              <p class="ct-design-system__token-var">--ct-font-sans</p>
            </article>
            <article class="ct-design-system__specimen">
              <h3>Rhythm</h3>
              <p class="ct-design-system__body-text">
                Spacing uses the 4px scale and restrained radii on admin surfaces.
              </p>
              <p class="ct-design-system__token-var">
                --ct-space-1 to --ct-space-6; --ct-radius-sm to --ct-radius-xl
              </p>
            </article>
          </div>
        </section>

        <section class="ct-design-system__section" id="colors">
          <h2>Colors</h2>
          <p class="ct-design-system__section-copy">
            Raw brand tokens anchor the palette. Component CSS should prefer semantic tokens unless
            it is defining a new semantic token.
          </p>
          <div class="ct-design-system__grid">
            {colorTokens.map((token) => (
              <ColorTokenCard token={token} />
            ))}
          </div>
        </section>

        <section class="ct-design-system__section" id="actions">
          <h2>Actions</h2>
          <div class="ct-design-system__grid">
            <article class="ct-design-system__example">
              <h3>Button hierarchy</h3>
              <ActionPreview />
              <p class="ct-design-system__example-note">
                One primary per region. Secondary actions use a quiet bordered fill.
              </p>
            </article>
            <article class="ct-design-system__example">
              <h3>Major secondary links</h3>
              <MajorLinkPreview />
              <p class="ct-design-system__example-note">
                Major feature links sit in a clean row; they are not oversized pill navigation.
              </p>
            </article>
            <article class="ct-design-system__example">
              <h3>Dense table actions</h3>
              <TableActionPreview />
              <p class="ct-design-system__example-note">
                Issued badge rows use the shared button class with the table action wrapper.
              </p>
            </article>
          </div>
        </section>

        <section class="ct-design-system__section" id="data">
          <h2>Data rows</h2>
          <p class="ct-design-system__section-copy">
            Tables should keep actions compact and states easy to scan without creating a second
            button language.
          </p>
          <DataPreview />
        </section>

        <section class="ct-design-system__section" id="classes">
          <h2>Approved action classes</h2>
          <ApprovedClasses />
        </section>
      </section>
    ),
  });
};
