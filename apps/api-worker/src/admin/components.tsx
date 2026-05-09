import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import type { TenantAssertionSummaryRecord } from "@credtrail/db";
import { formatIsoTimestamp } from "../utils/display-format";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export type AdminButtonVariant = "primary" | "secondary" | "ghost" | "danger";
export type AdminButtonSize = "default" | "tiny";

type ButtonType = "button" | "submit" | "reset";
type DataAttributes = Partial<Record<`data-${string}`, string>>;

export interface AdminSidebarLinkItem {
  href: string;
  label: string;
  isCurrent?: boolean;
  isSub?: boolean;
}

export interface AdminSidebarSection {
  label?: string;
  links: readonly AdminSidebarLinkItem[];
}

export interface AdminSidebarFooterLink {
  href: string;
  label: string;
  isExternal?: boolean;
  target?: "_blank";
  rel?: string;
}

export interface AdminTopbarChip {
  label: string;
  title?: string;
}

export interface AdminTableHeader {
  label: string;
  scope?: "col" | "row";
}

export const adminButtonClass = (input?: {
  variant?: AdminButtonVariant | undefined;
  size?: AdminButtonSize | undefined;
  extraClass?: string | undefined;
}): string => {
  const variant = input?.variant ?? "primary";
  const size = input?.size ?? "default";
  const classNames = ["ct-admin__button"];

  if (size === "tiny") {
    classNames.push("ct-admin__button--tiny");
  }

  if (variant !== "primary") {
    classNames.push(`ct-admin__button--${variant}`);
  }

  if (input?.extraClass !== undefined && input.extraClass.trim().length > 0) {
    classNames.push(input.extraClass.trim());
  }

  return classNames.join(" ");
};

export const AdminButton = ({
  id,
  type = "button",
  variant,
  size,
  disabled,
  form,
  formAction,
  className,
  ariaLabel,
  dataAttributes,
  children,
}: PropsWithChildren<{
  id?: string;
  type?: ButtonType;
  variant?: AdminButtonVariant;
  size?: AdminButtonSize;
  disabled?: boolean;
  form?: string;
  formAction?: string;
  className?: string;
  ariaLabel?: string;
  dataAttributes?: DataAttributes;
}>): HonoElement => {
  return (
    <button
      id={id}
      type={type}
      form={form}
      formaction={formAction}
      class={adminButtonClass({ variant, size, extraClass: className })}
      disabled={disabled}
      aria-label={ariaLabel}
      {...(dataAttributes ?? {})}
    >
      {children}
    </button>
  );
};

export const AdminButtonLink = ({
  href,
  variant,
  size,
  target,
  rel,
  className,
  ariaLabel,
  dataAttributes,
  children,
}: PropsWithChildren<{
  href: string;
  variant?: AdminButtonVariant;
  size?: AdminButtonSize;
  target?: "_blank";
  rel?: string;
  className?: string;
  ariaLabel?: string;
  dataAttributes?: DataAttributes;
}>): HonoElement => {
  return (
    <a
      class={adminButtonClass({ variant, size, extraClass: className })}
      href={href}
      target={target}
      rel={rel}
      aria-label={ariaLabel}
      {...(dataAttributes ?? {})}
    >
      {children}
    </a>
  );
};

export const AdminSidebarToggle = (): HonoElement => {
  return (
    <button
      type="button"
      class="ct-admin-topbar__toggle"
      aria-label="Toggle navigation"
      data-sidebar-toggle=""
    >
      <span aria-hidden="true">☰</span>
    </button>
  );
};

export const AdminSidebar = (input: {
  brandHref: string;
  sections: readonly AdminSidebarSection[];
  footerLinks: readonly AdminSidebarFooterLink[];
}): HonoElement => {
  return (
    <aside class="ct-admin-sidebar">
      <a class="ct-admin-sidebar__brand" href={input.brandHref}>
        CredTrail
      </a>
      <nav class="ct-admin-sidebar__nav" aria-label="Admin navigation">
        {input.sections.map((section) => (
          <>
            {section.label === undefined ? null : (
              <p class="ct-admin-sidebar__section-label">{section.label}</p>
            )}
            {section.links.map((link) => {
              const className =
                link.isSub === true
                  ? "ct-admin-sidebar__link ct-admin-sidebar__link--sub"
                  : "ct-admin-sidebar__link";

              return (
                <a
                  class={className}
                  href={link.href}
                  aria-current={link.isCurrent === true ? "page" : undefined}
                >
                  {link.label}
                </a>
              );
            })}
          </>
        ))}
      </nav>
      <div class="ct-admin-sidebar__footer">
        {input.footerLinks.map((link) => {
          const className =
            link.isExternal === true
              ? "ct-admin-sidebar__footer-link ct-admin-sidebar__link--external"
              : "ct-admin-sidebar__footer-link";

          return (
            <a class={className} href={link.href} target={link.target} rel={link.rel}>
              {link.label}
            </a>
          );
        })}
      </div>
    </aside>
  );
};

export const AdminTopbar = (input: {
  title: string;
  chips: readonly AdminTopbarChip[];
  userLabel: string;
  userTitle: string;
}): HonoElement => {
  return (
    <header class="ct-admin-topbar">
      <AdminSidebarToggle />
      <p class="ct-admin-topbar__title">{input.title}</p>
      <div class="ct-admin-topbar__user">
        {input.chips.map((chip) => (
          <span class="ct-admin-topbar__chip" title={chip.title}>
            {chip.label}
          </span>
        ))}
        <span title={input.userTitle}>{input.userLabel}</span>
      </div>
    </header>
  );
};

export const AdminShell = ({
  sidebar,
  topbar,
  contentClassName = "ct-admin-content",
  children,
}: PropsWithChildren<{
  sidebar: HonoElement;
  topbar: HonoElement;
  contentClassName?: string;
}>): HonoElement => {
  return (
    <div class="ct-admin-shell">
      {sidebar}
      <div class="ct-admin-main">
        {topbar}
        <div class={contentClassName}>{children}</div>
      </div>
    </div>
  );
};

export const AdminCtaLink = ({
  href,
  target,
  rel,
  className,
  ariaLabel,
  dataAttributes,
  children,
}: PropsWithChildren<{
  href: string;
  target?: "_blank";
  rel?: string;
  className?: string;
  ariaLabel?: string;
  dataAttributes?: DataAttributes;
}>): HonoElement => {
  const classNames = ["ct-admin__cta-link"];

  if (className !== undefined && className.trim().length > 0) {
    classNames.push(className.trim());
  }

  return (
    <a
      class={classNames.join(" ")}
      href={href}
      target={target}
      rel={rel}
      aria-label={ariaLabel}
      {...(dataAttributes ?? {})}
    >
      {children}
    </a>
  );
};

export const AdminMeta = ({
  as = "div",
  children,
}: PropsWithChildren<{
  as?: "div" | "span" | "p" | "dt";
}>): HonoElement => {
  switch (as) {
    case "span":
      return <span class="ct-admin__meta">{children}</span>;
    case "p":
      return <p class="ct-admin__meta">{children}</p>;
    case "dt":
      return <dt class="ct-admin__meta">{children}</dt>;
    case "div":
      return <div class="ct-admin__meta">{children}</div>;
  }
};

export const AdminStatusPill = ({
  tone,
  children,
}: PropsWithChildren<{
  tone?: string | null;
}>): HonoElement => {
  const normalizedTone = tone?.trim();
  const className =
    normalizedTone === undefined || normalizedTone.length === 0
      ? "ct-admin__status-pill"
      : `ct-admin__status-pill ct-admin__status-pill--${normalizedTone}`;

  return <span class={className}>{children}</span>;
};

export const AdminEmptyTableRow = ({
  colSpan,
  children,
}: PropsWithChildren<{
  colSpan: number;
}>): HonoElement => {
  return (
    <tr>
      <td colspan={colSpan} class="ct-admin__empty">
        {children}
      </td>
    </tr>
  );
};

export const AdminTable = ({
  headers,
  id,
  tbodyId,
  compact = false,
  wrapperClassName,
  tableClassName,
  tbodyDataAttributes,
  children,
}: PropsWithChildren<{
  headers: readonly (string | AdminTableHeader)[];
  id?: string;
  tbodyId?: string;
  compact?: boolean;
  wrapperClassName?: string;
  tableClassName?: string;
  tbodyDataAttributes?: DataAttributes;
}>): HonoElement => {
  const wrapperClass =
    wrapperClassName === undefined || wrapperClassName.trim().length === 0
      ? "ct-admin__table-wrap"
      : wrapperClassName.trim();
  const tableClasses = [
    "ct-admin__table",
    compact ? "ct-admin__table--compact" : "",
    tableClassName?.trim() ?? "",
  ].filter((className) => className.length > 0);

  return (
    <div class={wrapperClass}>
      <table id={id} class={tableClasses.join(" ")}>
        <thead>
          <tr>
            {headers.map((header) => {
              const label = typeof header === "string" ? header : header.label;
              const scope = typeof header === "string" ? "col" : (header.scope ?? "col");

              return <th scope={scope}>{label}</th>;
            })}
          </tr>
        </thead>
        <tbody id={tbodyId} {...(tbodyDataAttributes ?? {})}>
          {children}
        </tbody>
      </table>
    </div>
  );
};

export const AdminActionBar = ({
  ariaLabel,
  children,
}: PropsWithChildren<{
  ariaLabel: string;
}>): HonoElement => {
  return (
    <div class="ct-admin__action-bar" role="group" aria-label={ariaLabel}>
      {children}
    </div>
  );
};

export const AdminActionMenu = ({
  ariaLabel,
  triggerLabel = "...",
  children,
}: PropsWithChildren<{
  ariaLabel: string;
  triggerLabel?: string;
}>): HonoElement => {
  return (
    <details class="ct-admin__action-menu">
      <summary
        class={adminButtonClass({
          variant: "secondary",
          size: "tiny",
          extraClass: "ct-admin__action-menu-trigger",
        })}
        aria-label={ariaLabel}
      >
        {triggerLabel}
      </summary>
      <div class="ct-admin__action-menu-popover">{children}</div>
    </details>
  );
};

export const AdminActionMenuLink = ({
  href,
  target,
  rel,
  tone,
  dataAttributes,
  children,
}: PropsWithChildren<{
  href: string;
  target?: "_blank";
  rel?: string;
  tone?: "danger";
  dataAttributes?: DataAttributes;
}>): HonoElement => {
  const className =
    tone === "danger"
      ? "ct-admin__action-menu-item ct-admin__action-menu-item--danger"
      : "ct-admin__action-menu-item";

  return (
    <a class={className} href={href} target={target} rel={rel} {...(dataAttributes ?? {})}>
      {children}
    </a>
  );
};

export const AdminActionMenuButton = ({
  type = "button",
  tone,
  dataAttributes,
  children,
}: PropsWithChildren<{
  type?: ButtonType;
  tone?: "danger";
  dataAttributes?: DataAttributes;
}>): HonoElement => {
  const className =
    tone === "danger"
      ? "ct-admin__action-menu-item ct-admin__action-menu-item--danger"
      : "ct-admin__action-menu-item";

  return (
    <button type={type} class={className} {...(dataAttributes ?? {})}>
      {children}
    </button>
  );
};

export const IssuedBadgeActions = (input: {
  assertionId: string;
  viewBadgeHref: string;
  rawJsonHref: string;
  canRevoke: boolean;
}): HonoElement => {
  return (
    <AdminActionBar ariaLabel={`Actions for assertion ${input.assertionId}`}>
      <AdminButtonLink
        href={input.viewBadgeHref}
        size="tiny"
        target="_blank"
        rel="noopener noreferrer"
      >
        Open
      </AdminButtonLink>
      <AdminButton
        variant="secondary"
        size="tiny"
        dataAttributes={{
          "data-issued-action": "audit",
          "data-assertion-id": input.assertionId,
        }}
      >
        Audit
      </AdminButton>
      <AdminActionMenu ariaLabel={`More actions for assertion ${input.assertionId}`}>
        <AdminActionMenuLink href={input.rawJsonHref} target="_blank" rel="noopener noreferrer">
          Open JSON-LD
        </AdminActionMenuLink>
        {input.canRevoke ? (
          <AdminActionMenuButton
            tone="danger"
            dataAttributes={{
              "data-issued-action": "revoke",
              "data-assertion-id": input.assertionId,
            }}
          >
            Revoke badge
          </AdminActionMenuButton>
        ) : null}
      </AdminActionMenu>
    </AdminActionBar>
  );
};

export const IssuedBadgeRow = (input: { assertion: TenantAssertionSummaryRecord }): HonoElement => {
  const assertion = input.assertion;
  const viewBadgeHref = `/badges/${encodeURIComponent(assertion.assertionId)}`;
  const rawJsonHref = `/credentials/v1/${encodeURIComponent(assertion.assertionId)}/jsonld`;

  return (
    <tr data-issued-badge-row="true">
      <td>{formatIsoTimestamp(assertion.issuedAt)}</td>
      <td>
        <strong>{assertion.recipientIdentity}</strong>
      </td>
      <td>
        <strong>{assertion.badgeTitle}</strong>
        <AdminMeta>{assertion.badgeTemplateId}</AdminMeta>
      </td>
      <td>
        <AdminStatusPill tone={assertion.state}>{assertion.state}</AdminStatusPill>
        <AdminMeta>{assertion.source}</AdminMeta>
      </td>
      <td>
        <div class="ct-admin__assertion-id">{assertion.assertionId}</div>
        {assertion.publicId === null ? null : <AdminMeta>public: {assertion.publicId}</AdminMeta>}
      </td>
      <td class="ct-admin__issued-actions-cell">
        <div class="ct-admin__issued-actions">
          <IssuedBadgeActions
            assertionId={assertion.assertionId}
            viewBadgeHref={viewBadgeHref}
            rawJsonHref={rawJsonHref}
            canRevoke={assertion.state !== "revoked"}
          />
        </div>
      </td>
    </tr>
  );
};

export const IssuedBadgeRows = (input: {
  assertions: readonly TenantAssertionSummaryRecord[];
  emptyMessage?: string;
}): HonoElement => {
  if (input.assertions.length === 0) {
    return (
      <AdminEmptyTableRow colSpan={6}>
        {input.emptyMessage ?? "No assertions matched the selected filters."}
      </AdminEmptyTableRow>
    );
  }

  return (
    <>
      {input.assertions.map((assertion) => (
        <IssuedBadgeRow assertion={assertion} />
      ))}
    </>
  );
};

export const renderIssuedBadgeRowsToString = (
  assertions: readonly TenantAssertionSummaryRecord[],
): string => {
  const renderable = (<IssuedBadgeRows assertions={assertions} />) as { toString(): string };

  return renderable.toString();
};
