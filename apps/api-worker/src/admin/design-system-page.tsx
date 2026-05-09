import type { HtmlEscapedString } from "hono/utils/html";
import {
  AdminButton,
  AdminButtonLink,
  AdminCtaLink,
  AdminEmptyTableRow,
  AdminMeta,
  AdminSidebarToggle,
  AdminStatusPill,
  AdminTable,
  IssuedBadgeActions,
} from "./components";
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

interface ComponentDoc {
  name: string;
  source: string;
  purpose: string;
  usage: string;
}

interface TokenPipelineDoc {
  label: string;
  value: string;
  detail: string;
}

const appPageExample = `return appPage({
  title: "Operations | CredTrail",
  variant: "admin",
  assets: ["institutionAdminCss"],
  body: <section class="ct-admin-content">...</section>,
});`;

const styleDictionaryExample = `pnpm build:design-tokens

# Source
design/tokens/credtrail.tokens.json

# Generated app assets
apps/api-worker/src/ui/page-assets/content/generated/design-tokens.css
apps/api-worker/src/ui/page-assets/content/generated/design-tokens-css.ts`;

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

const componentDocs: readonly ComponentDoc[] = [
  {
    name: "PageLayout",
    source: "packages/ui-components/src/index.tsx",
    purpose: "Owns the HTML document shell, font loading, favicon tags, and body variant.",
    usage:
      "Used by renderAppPage and renderAppPageToString; page modules should not render full-document HTML.",
  },
  {
    name: "appPage",
    source: "apps/api-worker/src/ui/render-page.tsx",
    purpose: "Creates the typed AppPage contract used by server-rendered Hono JSX pages.",
    usage: "Page modules return appPage with title, variant, assets, and body.",
  },
  {
    name: "renderAppPage",
    source: "apps/api-worker/src/ui/render-page.tsx",
    purpose: "Renders an AppPage from route handlers through the registered Hono JSX renderer.",
    usage: "Routes call renderAppPage after auth, validation, and data loading.",
  },
  {
    name: "PageAssets",
    source: "apps/api-worker/src/ui/page-assets/index.tsx",
    purpose: "Emits content-hashed stylesheet and script tags from the typed page asset registry.",
    usage: "Use appPage assets instead of hand-writing stylesheet or script URLs.",
  },
  {
    name: "AdminButton",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Centralizes admin button class composition for native button elements.",
    usage: "Use variant, size, and native form props instead of hand-writing button classes.",
  },
  {
    name: "AdminShell",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Owns the standard admin page grid with shared sidebar, topbar, main, and content.",
    usage: "Use for institution admin pages instead of recreating ct-admin-shell markup.",
  },
  {
    name: "AdminSidebar",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Renders sidebar sections, sublinks, current-page state, and footer links from data.",
    usage: "Use a typed nav model so admin pages do not hand-write duplicate sidebar markup.",
  },
  {
    name: "AdminTopbar",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Renders the responsive sidebar toggle, tenant title, role chips, and signed-in user.",
    usage: "Use in AdminShell topbar slots instead of recreating topbar structure per page.",
  },
  {
    name: "AdminButtonLink",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Renders anchor actions with the same variants and sizes as admin buttons.",
    usage: "Use for reset, export, and route links that behave like secondary or primary actions.",
  },
  {
    name: "AdminCtaLink",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Renders the lower-radius major-link row item for true cross-surface resources.",
    usage:
      "Use for links like public badge, standards mapping, and CSV template downloads; avoid it for destinations already in the sidebar.",
  },
  {
    name: "AdminActionBar",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Groups row-level actions with the correct role, label, and compact spacing class.",
    usage: "Use for dense table and record actions where several commands sit together.",
  },
  {
    name: "AdminTable",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Owns standard admin table wrapper, header, compact mode, and typed tbody hooks.",
    usage: "Use for admin tables before hand-writing ct-admin__table-wrap and table headers.",
  },
  {
    name: "AdminEmptyTableRow",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Renders consistent empty-state rows with the approved ct-admin__empty class.",
    usage: "Use inside AdminTable or existing admin tables whenever a collection has no rows.",
  },
  {
    name: "AdminMeta",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Centralizes subdued admin metadata text across div, span, paragraph, and dt tags.",
    usage: "Use for IDs, source notes, secondary timestamps, and no-action labels.",
  },
  {
    name: "AdminStatusPill",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Owns status pill class composition and optional tone modifiers.",
    usage: "Use for table state, role labels, and small quantitative chips.",
  },
  {
    name: "AdminSidebarToggle",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Owns the responsive admin sidebar toggle markup and accessibility label.",
    usage: "Use in admin topbars instead of recreating hamburger button markup in page JSX.",
  },
  {
    name: "IssuedBadgeActions",
    source: "apps/api-worker/src/admin/components.tsx",
    purpose: "Owns the issued-badge Open, Audit, JSON-LD, and revoke action pattern.",
    usage: "Use this instead of recreating issued-badge action markup in server-rendered JSX.",
  },
  {
    name: "RuleBuilderConditionCardTemplate",
    source: "apps/api-worker/src/admin/institution-admin-rule-builder-page.tsx",
    purpose: "Keeps client-added condition card structure in server-rendered JSX.",
    usage: "Client JavaScript clones this template, then only fills dynamic field values.",
  },
  {
    name: "PublicBadgeButtonLink / PublicBadgeButton",
    source: "apps/api-worker/src/badges/public-badge-pages.tsx",
    purpose: "Own the public credential action button classes for links and native buttons.",
    usage: "Use for wallet, download, validator, LinkedIn, and copy actions on public pages.",
  },
  {
    name: "LoginSubmitButton / LoginActionLink",
    source: "apps/api-worker/src/auth/pages.tsx",
    purpose: "Own the login CTA class for submit buttons and enterprise sign-in links.",
    usage: "Use on auth pages instead of hand-writing ct-login__submit.",
  },
  {
    name: "LtiLaunchCard / LtiSubmitButton",
    source: "apps/api-worker/src/lti/pages.tsx",
    purpose:
      "Centralize LTI card and submit action markup across launch, deep-link, and admin pages.",
    usage: "Use for LTI launch cards, roster issuance actions, and registration forms.",
  },
  {
    name: "LearnerButton / LearnerButtonRow",
    source: "apps/api-worker/src/learner/pages.tsx",
    purpose: "Own learner dashboard button variants and grouped action rows.",
    usage: "Use for learner DID settings and badge claim actions.",
  },
];

const tokenPipelineDocs: readonly TokenPipelineDoc[] = [
  {
    label: "Token source",
    value: "design/tokens/credtrail.tokens.json",
    detail:
      "Edit this JSON when a shared color, font, spacing, radius, motion, or elevation value changes.",
  },
  {
    label: "Build config",
    value: "style-dictionary.config.mjs",
    detail: "Style Dictionary transforms the token JSON into CSS custom properties.",
  },
  {
    label: "Generated CSS",
    value: "apps/api-worker/src/ui/page-assets/content/generated/design-tokens.css",
    detail: "Canonical generated CSS output. Do not edit by hand.",
  },
  {
    label: "Generated TS wrapper",
    value: "apps/api-worker/src/ui/page-assets/content/generated/design-tokens-css.ts",
    detail:
      "Imported by foundationCss so the Worker serves generated tokens through the existing asset system.",
  },
  {
    label: "Drift check",
    value: "pnpm check:design-tokens",
    detail: "Rebuilds generated files and fails if checked-in generated assets are stale.",
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

const ComponentDocCard = (input: { doc: ComponentDoc }): HonoElement => {
  return (
    <article class="ct-design-system__doc-card">
      <div class="ct-design-system__doc-card-head">
        <h3>{input.doc.name}</h3>
        <code>{input.doc.source}</code>
      </div>
      <p class="ct-design-system__body-text">{input.doc.purpose}</p>
      <p class="ct-design-system__meta-text">{input.doc.usage}</p>
    </article>
  );
};

const PipelineDocRow = (input: { doc: TokenPipelineDoc }): HonoElement => {
  return (
    <article class="ct-design-system__pipeline-row">
      <div>
        <h3>{input.doc.label}</h3>
        <code>{input.doc.value}</code>
      </div>
      <p>{input.doc.detail}</p>
    </article>
  );
};

const CodeBlock = (input: { label: string; code: string }): HonoElement => {
  return (
    <figure class="ct-design-system__code-block">
      <figcaption>{input.label}</figcaption>
      <pre>
        <code>{input.code}</code>
      </pre>
    </figure>
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
      <AdminButtonLink href="#actions">Primary</AdminButtonLink>
      <AdminButton variant="secondary">Secondary</AdminButton>
      <AdminButton variant="ghost">Tertiary</AdminButton>
      <AdminButton variant="danger">Danger</AdminButton>
      <AdminButton disabled={true}>Working</AdminButton>
    </div>
  );
};

const MajorLinkPreview = (): HonoElement => {
  return (
    <div class="ct-design-system__example-row">
      <AdminCtaLink href="#actions">Rule library and templates</AdminCtaLink>
      <AdminCtaLink href="#actions">Review queue</AdminCtaLink>
      <AdminCtaLink href="#actions">Download CSV template</AdminCtaLink>
    </div>
  );
};

const TableActionPreview = (): HonoElement => {
  return (
    <div class="ct-design-system__action-demo">
      <IssuedBadgeActions
        assertionId="sakai:1df79bc6-6a08-42a2"
        viewBadgeHref="#actions"
        rawJsonHref="#actions"
        canRevoke={true}
      />
    </div>
  );
};

const SidebarTogglePreview = (): HonoElement => {
  return (
    <div class="ct-design-system__example-row ct-design-system__sidebar-toggle-demo">
      <AdminSidebarToggle />
    </div>
  );
};

const DataPreview = (): HonoElement => {
  return (
    <div class="ct-design-system__table-demo">
      <AdminTable headers={["Issued", "Recipient", "State", "Assertion", "Actions"]}>
        <tr>
          <td>5/8/2026</td>
          <td>
            <span class="ct-admin__member-identity">ern@umich.edu</span>
            <AdminMeta as="span">Sakai roster import</AdminMeta>
          </td>
          <td>
            <AdminStatusPill tone="active">active</AdminStatusPill>
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
        <AdminEmptyTableRow colSpan={5}>Empty rows use the same table language.</AdminEmptyTableRow>
      </AdminTable>
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
            Internal catalog for JSX page components, the Style Dictionary token pipeline, admin
            typography, button hierarchy, secondary link rows, and table actions.
          </p>
        </header>

        <nav class="ct-design-system__nav" aria-label="Styleguide sections">
          <a href="#foundations">Foundations</a>
          <a href="#jsx-components">JSX components</a>
          <a href="#style-dictionary">Style Dictionary</a>
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

        <section class="ct-design-system__section" id="jsx-components">
          <h2>JSX components</h2>
          <p class="ct-design-system__section-copy">
            CredTrail app pages are server-rendered Hono JSX. Shared page structure belongs in typed
            components and app page helpers, not route handlers or full-document strings.
          </p>
          <div class="ct-design-system__doc-grid">
            {componentDocs.map((doc) => (
              <ComponentDocCard doc={doc} />
            ))}
          </div>
          <CodeBlock label="Page module pattern" code={appPageExample} />
        </section>

        <section class="ct-design-system__section" id="style-dictionary">
          <h2>Style Dictionary</h2>
          <p class="ct-design-system__section-copy">
            Style Dictionary is the source-to-asset bridge. Edit token JSON first, rebuild generated
            assets, and let foundationCss distribute the resulting custom properties.
          </p>
          <div class="ct-design-system__pipeline">
            {tokenPipelineDocs.map((doc) => (
              <PipelineDocRow doc={doc} />
            ))}
          </div>
          <CodeBlock label="Token build flow" code={styleDictionaryExample} />
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
            <article class="ct-design-system__example">
              <h3>Responsive topbar toggle</h3>
              <SidebarTogglePreview />
              <p class="ct-design-system__example-note">
                Sidebar toggles share one accessible component and button reset.
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
