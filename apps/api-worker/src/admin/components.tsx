import { assertionLifecycleLabels } from "../badges/assertion-lifecycle-labels";
import { learnerRecordLink } from "./learner-record-link";
import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import type { TenantAssertionSummaryRecord } from "@credtrail/db";
import type { BadgeRuleReviewQueueEntryView } from "../badge-rule-review-queue-workspace";
import { formatBadgeRuleReviewQueueSummary } from "../badge-rule-review-queue-workspace";
import type { CtDataAttributes } from "../ui/jsx-utils";
import { CtCheckboxField, CtField, CtForm, type CtCheckboxType } from "../ui/forms";
import { AdminButton, AdminButtonLink, type AdminButtonVariant } from "./actions";
import { adminStatusPillClass } from "./admin-status-pill-class";
import { formatIsoTimestamp } from "../utils/display-format";
export {
  AdminActions,
  AdminButton,
  AdminButtonLink,
  adminButtonClass,
  type AdminButtonSize,
  type AdminButtonVariant,
} from "./actions";
export { AdminSidebar, type AdminSidebarFooterLink, type AdminSidebarSection } from "./sidebar";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

type FormMethod = "get" | "post";
type DataAttributes = CtDataAttributes;

export interface AdminTopbarChip {
  label: string;
  title?: string;
}

export interface AdminTableHeader {
  label: string | HonoElement;
  scope?: "col" | "row";
  ariaSort?: "ascending" | "descending" | "none";
}

export type AdminPanelVariant = "default" | "table" | "nested";

const normalizedExtraClass = (className: string | undefined): string | undefined => {
  const normalizedClassName = className?.trim();

  return normalizedClassName === undefined || normalizedClassName.length === 0
    ? undefined
    : normalizedClassName;
};

const adminPanelClass = (input?: {
  variant?: AdminPanelVariant | undefined;
  stack?: boolean | undefined;
  extraClass?: string | undefined;
}): string => {
  const variant = input?.variant ?? "default";
  const stack = input?.stack ?? true;
  const classNames = ["ct-admin__panel"];

  if (variant !== "default") {
    classNames.push(`ct-admin__panel--${variant}`);
  }

  const extraClass = normalizedExtraClass(input?.extraClass);

  if (extraClass !== undefined) {
    classNames.push(extraClass);
  }

  if (stack) {
    classNames.push("ct-stack");
  }

  return classNames.join(" ");
};

const adminMetricCardClass = (input?: {
  stack?: boolean | undefined;
  extraClass?: string | undefined;
}): string => {
  const classNames = ["ct-admin__metric-card"];

  if (input?.stack === true) {
    classNames.push("ct-stack");
  }

  const extraClass = normalizedExtraClass(input?.extraClass);

  if (extraClass !== undefined) {
    classNames.push(extraClass);
  }

  return classNames.join(" ");
};

export const AdminPageHeader = ({
  as = "div",
  title,
  description,
  compact = false,
  className,
  note,
}: {
  as?: "div" | "header";
  title: string;
  description: string | HonoElement;
  compact?: boolean;
  className?: string;
  note?: HonoElement | null;
}): HonoElement => {
  const classNames = [
    "ct-admin-page-header",
    compact ? "ct-admin-page-header--compact" : "",
    normalizedExtraClass(className) ?? "",
  ].filter((entry) => entry.length > 0);
  const content = (
    <>
      <h1>{title}</h1>
      <p>{description}</p>
      {note ?? null}
    </>
  );

  if (as === "header") {
    return <header class={classNames.join(" ")}>{content}</header>;
  }

  return <div class={classNames.join(" ")}>{content}</div>;
};

const AdminSidebarToggle = (): HonoElement => {
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

export const AdminPanel = ({
  as = "article",
  id,
  variant,
  stack,
  className,
  dataAttributes,
  children,
}: PropsWithChildren<{
  as?: "article" | "section";
  id?: string;
  variant?: AdminPanelVariant;
  stack?: boolean;
  className?: string;
  dataAttributes?: DataAttributes;
}>): HonoElement => {
  const panelClass = adminPanelClass({ variant, stack, extraClass: className });

  if (as === "section") {
    return (
      <section id={id} class={panelClass} {...(dataAttributes ?? {})}>
        {children}
      </section>
    );
  }

  return (
    <article id={id} class={panelClass} {...(dataAttributes ?? {})}>
      {children}
    </article>
  );
};

export const AdminListHeader = ({
  title,
  titleId,
  description,
  action,
}: {
  title: string | HonoElement;
  titleId?: string;
  description?: string | HonoElement | null;
  action?: HonoElement | null;
}): HonoElement => {
  return (
    <div class="ct-admin__list-header">
      <div class="ct-admin__list-header-copy">
        <h2 id={titleId}>{title}</h2>
        {description === null || description === undefined ? null : <p>{description}</p>}
      </div>
      {action ?? null}
    </div>
  );
};

export const AdminInlinePanelTriggerButton = ({
  panelId,
  expanded = false,
  variant = "secondary",
  children,
}: PropsWithChildren<{
  panelId: string;
  expanded?: boolean;
  variant?: AdminButtonVariant;
}>): HonoElement => {
  return (
    <AdminButton
      type="button"
      variant={variant}
      ariaControls={panelId}
      ariaExpanded={expanded}
      dataAttributes={{ "data-admin-inline-panel-trigger": panelId }}
    >
      {children}
    </AdminButton>
  );
};

export const AdminInlinePanelCloseButton = ({
  panelId,
  children,
}: PropsWithChildren<{
  panelId: string;
}>): HonoElement => {
  return (
    <AdminButton
      type="button"
      variant="secondary"
      dataAttributes={{ "data-admin-inline-panel-close": panelId }}
    >
      {children}
    </AdminButton>
  );
};

export const AdminInlineActionPanel = ({
  id,
  title,
  description,
  hidden = true,
  children,
}: PropsWithChildren<{
  id: string;
  title: string | HonoElement;
  description?: string | HonoElement | null;
  hidden?: boolean;
}>): HonoElement => {
  return (
    <div id={id} class="ct-admin__inline-action-panel" hidden={hidden ? true : undefined}>
      <div>
        <h3>{title}</h3>
        {description === null || description === undefined ? null : <p>{description}</p>}
      </div>
      {children}
    </div>
  );
};

export const AdminMetricCard = ({
  stack,
  className,
  dataAttributes,
  children,
}: PropsWithChildren<{
  stack?: boolean;
  className?: string;
  dataAttributes?: DataAttributes;
}>): HonoElement => {
  return (
    <article
      class={adminMetricCardClass({ stack, extraClass: className })}
      {...(dataAttributes ?? {})}
    >
      {children}
    </article>
  );
};

export const AdminWorkspaceCard = ({
  href,
  ariaLabel,
  children,
}: PropsWithChildren<{
  href?: string;
  ariaLabel?: string;
}>): HonoElement => {
  const className = "ct-admin__workspace-card ct-stack";

  if (href === undefined) {
    return <article class={className}>{children}</article>;
  }

  return (
    <a class={className} href={href} aria-label={ariaLabel}>
      {children}
    </a>
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
  return <span class={adminStatusPillClass(tone)}>{children}</span>;
};

export const AdminEmptyTableRow = ({
  colSpan,
  children,
}: PropsWithChildren<{
  colSpan: number;
}>): HonoElement => {
  return (
    <tr role="row">
      <td role="cell" colspan={colSpan} class="ct-admin__empty">
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
      <table id={id} class={tableClasses.join(" ")} role="table">
        <thead role="rowgroup">
          <tr role="row">
            {headers.map((header) => {
              const label = typeof header === "string" ? header : header.label;
              const scope = typeof header === "string" ? "col" : (header.scope ?? "col");
              const ariaSort = typeof header === "string" ? undefined : header.ariaSort;

              return (
                <th
                  scope={scope}
                  aria-sort={ariaSort}
                  role={scope === "row" ? "rowheader" : "columnheader"}
                >
                  {label}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody id={tbodyId} role="rowgroup" {...(tbodyDataAttributes ?? {})}>
          {children}
        </tbody>
      </table>
    </div>
  );
};

export const AdminForm = ({
  id,
  method,
  action,
  encType,
  className = "ct-admin__form ct-stack",
  dataAttributes,
  hidden,
  children,
}: PropsWithChildren<{
  id?: string;
  method?: FormMethod;
  action?: string;
  encType?: "multipart/form-data";
  className?: string;
  dataAttributes?: DataAttributes;
  hidden?: boolean;
}>): HonoElement => {
  return (
    <CtForm
      id={id}
      method={method}
      action={action}
      encType={encType}
      className={className}
      hidden={hidden}
      dataAttributes={dataAttributes}
    >
      {children}
    </CtForm>
  );
};

export const AdminField = ({
  id,
  label,
  className,
  inline,
  compact,
  children,
}: PropsWithChildren<{
  id?: string;
  label: string;
  className?: string;
  inline?: boolean;
  compact?: boolean;
}>): HonoElement => {
  const classes = className === undefined ? "ct-admin__field" : `ct-admin__field ${className}`;
  return (
    <CtField id={id} label={label} className={classes} inline={inline} compact={compact}>
      {children}
    </CtField>
  );
};

export const AdminCheckboxRow = ({
  name,
  value,
  label,
  checked,
  type = "checkbox",
  disabled,
  form,
  describedBy,
  dataAttributes,
}: {
  name: string;
  label: string;
  value?: string;
  checked?: boolean;
  type?: CtCheckboxType;
  disabled?: boolean;
  form?: string;
  describedBy?: string | readonly string[];
  dataAttributes?: DataAttributes;
}): HonoElement => {
  return (
    <CtCheckboxField
      name={name}
      value={value}
      label={label}
      checked={checked}
      type={type}
      disabled={disabled}
      form={form}
      describedBy={describedBy}
      dataAttributes={dataAttributes}
      className="ct-admin__checkbox-row"
    />
  );
};

export const AdminFieldset = ({
  legend,
  children,
}: PropsWithChildren<{
  legend: string;
}>): HonoElement => {
  return (
    <fieldset class="ct-admin__fieldset ct-stack">
      <legend>{legend}</legend>
      {children}
    </fieldset>
  );
};

/** Renders admin feedback, with optional polite announcements for client-side updates. */
export const AdminStatus = ({
  id,
  tone,
  live = false,
  children,
}: PropsWithChildren<{
  id?: string;
  tone?: "info" | "success" | "warning" | "error";
  live?: boolean;
}>): HonoElement => {
  return (
    <p
      id={id}
      class="ct-admin__status"
      data-tone={tone}
      role={live ? "status" : undefined}
      aria-live={live ? "polite" : undefined}
    >
      {children}
    </p>
  );
};

const AdminActionBar = ({
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

/**
 * Renders a row-scoped action panel. Callers must pass a stable page-unique menuId
 * so the trigger can reference the panel with aria-controls.
 */
export const AdminActionMenu = ({
  menuId,
  ariaLabel,
  triggerLabel = "⋮",
  children,
}: PropsWithChildren<{
  menuId: string;
  ariaLabel: string;
  triggerLabel?: string;
}>): HonoElement => {
  return (
    <span class="ct-admin__action-menu">
      <button
        type="button"
        class="ct-admin__icon-button ct-admin__action-menu-trigger"
        aria-controls={menuId}
        aria-expanded="false"
        aria-label={ariaLabel}
        data-action-menu-trigger={menuId}
      >
        {triggerLabel}
      </button>
      <div id={menuId} class="ct-admin__action-menu-popover" data-action-menu-panel hidden>
        {children}
      </div>
    </span>
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

const IssuedBadgeActions = (input: {
  assertionId: string;
  viewBadgeHref: string;
  rawJsonHref: string;
  evidenceHref: string;
  statusHref: string;
}): HonoElement => {
  return (
    <AdminActionBar ariaLabel={`Actions for assertion ${input.assertionId}`}>
      <AdminButtonLink href={input.evidenceHref} size="tiny" variant="primary">
        View record
      </AdminButtonLink>
      <AdminButtonLink
        href={input.viewBadgeHref}
        variant="secondary"
        size="tiny"
        target="_blank"
        rel="noopener noreferrer"
      >
        View public badge
      </AdminButtonLink>
      <AdminActionMenu
        menuId={`issued-badge-action-menu-${input.assertionId}`}
        ariaLabel={`More actions for assertion ${input.assertionId}`}
      >
        <AdminActionMenuLink href={input.rawJsonHref} target="_blank" rel="noopener noreferrer">
          Open JSON-LD
        </AdminActionMenuLink>
        <AdminActionMenuLink href={input.statusHref}>Manage status</AdminActionMenuLink>
      </AdminActionMenu>
    </AdminActionBar>
  );
};

const IssuedBadgeRow = (input: {
  showNotificationRetry?: boolean | undefined;
  learnerReturnHref?: string | undefined;
  assertion: TenantAssertionSummaryRecord;
  evidenceHref: string;
  statusHref: string;
}): HonoElement => {
  const assertion = input.assertion;
  const viewBadgeHref = `/badges/${encodeURIComponent(assertion.publicId ?? assertion.assertionId)}`;
  const rawJsonHref = `/credentials/v1/${encodeURIComponent(assertion.assertionId)}/jsonld`;

  const learnerHref = learnerRecordLink(
    assertion.tenantId,
    assertion.recipientIdentityType,
    assertion.recipientIdentity,
    input.learnerReturnHref,
  );

  return (
    <tr data-issued-badge-row="true" role="row">
      <td data-label="Learner" role="cell">
        <strong>{assertion.recipientIdentity}</strong>
        {learnerHref === null ? null : (
          <div>
            <a href={learnerHref}>View learner record</a>
          </div>
        )}
      </td>
      <td data-label="Badge" role="cell">
        <strong>{assertion.badgeTitle}</strong>
      </td>
      <td data-label="Issued" role="cell">
        {formatIsoTimestamp(assertion.issuedAt)} UTC
      </td>
      <td data-label="Status" role="cell">
        <AdminStatusPill tone={assertion.state}>
          {assertionLifecycleLabels[assertion.state]}
        </AdminStatusPill>
      </td>
      <td data-label="Actions" role="cell" class="ct-admin__issued-actions-cell">
        <div class="ct-admin__issued-actions">
          {input.showNotificationRetry ? (
            <AdminButtonLink
              href={`/tenants/${encodeURIComponent(assertion.tenantId)}/admin/operations/issue/${encodeURIComponent(assertion.assertionId)}/receipt${input.learnerReturnHref ? `?${new URLSearchParams({ returnTo: input.learnerReturnHref })}` : ""}`}
              size="tiny"
            >
              Retry notification email
            </AdminButtonLink>
          ) : null}
          <IssuedBadgeActions
            assertionId={assertion.assertionId}
            viewBadgeHref={viewBadgeHref}
            rawJsonHref={rawJsonHref}
            evidenceHref={input.evidenceHref}
            statusHref={input.statusHref}
          />
        </div>
      </td>
    </tr>
  );
};

/** Describes elapsed waiting time without implying a review deadline. */
export const reviewWaitingLabel = (evaluatedAt: string, now: number): string => {
  const elapsed = now - Date.parse(evaluatedAt);
  if (!Number.isFinite(elapsed)) return "Waiting time unavailable";
  const days = Math.floor(Math.max(0, elapsed) / 86400000);
  return days === 0 ? "Waiting less than a day" : `Waiting ${days} ${days === 1 ? "day" : "days"}`;
};

const ReviewQueueRow = (input: {
  now?: number | undefined;
  reviewHref?: string | undefined;
  entry: BadgeRuleReviewQueueEntryView;
  resolveActionPath: string;
}): HonoElement => {
  const entry = input.entry;
  const ruleLabel = entry.ruleName ?? entry.ruleId;
  const summaryText = formatBadgeRuleReviewQueueSummary(entry.evaluationSummary);
  const isPending = entry.reviewStatus === "pending";

  return (
    <tr data-review-queue-row="true">
      <td>
        <time datetime={entry.evaluatedAt} title={entry.evaluatedAt}>
          {formatIsoTimestamp(entry.evaluatedAt)} UTC
        </time>
        {isPending && input.now !== undefined ? (
          <AdminMeta>{reviewWaitingLabel(entry.evaluatedAt, input.now)}</AdminMeta>
        ) : null}
      </td>
      <td>
        <strong>{entry.recipientIdentity}</strong>
      </td>
      <td>
        <strong>{ruleLabel}</strong>
        <AdminMeta>{entry.ruleId}</AdminMeta>
      </td>
      <td>{summaryText}</td>
      <td class="ct-admin__issued-actions-cell">
        {isPending ? (
          <AdminButtonLink
            href={
              input.reviewHref ??
              `${input.resolveActionPath.replace(/\/resolve$/, "")}?${new URLSearchParams({ review: entry.evaluationId })}#review-decision-panel`
            }
            variant="secondary"
            size="tiny"
          >
            Review decision
          </AdminButtonLink>
        ) : (
          <AdminButtonLink
            href={
              input.reviewHref ??
              `${input.resolveActionPath.replace(/\/resolve$/, "")}?${new URLSearchParams({ reviewStatus: "resolved", review: entry.evaluationId })}#review-decision-panel`
            }
            variant="secondary"
            size="tiny"
          >
            View decision
          </AdminButtonLink>
        )}
      </td>
    </tr>
  );
};

export const ReviewQueueRows = (input: {
  now?: number;
  reviewHrefForEntry?: (entry: BadgeRuleReviewQueueEntryView) => string;
  entries: readonly BadgeRuleReviewQueueEntryView[];
  resolveActionPath: string;
  emptyMessage?: string;
}): HonoElement => {
  if (input.entries.length === 0) {
    return (
      <AdminEmptyTableRow colSpan={5}>
        {input.emptyMessage ?? "No pending review queue entries."}
      </AdminEmptyTableRow>
    );
  }

  return (
    <>
      {input.entries.map((entry) => (
        <ReviewQueueRow
          entry={entry}
          now={input.now}
          resolveActionPath={input.resolveActionPath}
          reviewHref={input.reviewHrefForEntry?.(entry)}
        />
      ))}
    </>
  );
};

export const IssuedBadgeRows = (input: {
  showNotificationRetry?: boolean | undefined;
  learnerReturnHref?: string;
  assertions: readonly TenantAssertionSummaryRecord[];
  evidenceHrefForAssertion: (assertionId: string) => string;
  statusHrefForAssertion: (assertionId: string) => string;
  emptyMessage?: string;
}): HonoElement => {
  if (input.assertions.length === 0) {
    return (
      <AdminEmptyTableRow colSpan={5}>
        {input.emptyMessage ?? "No assertions matched the selected filters."}
      </AdminEmptyTableRow>
    );
  }

  return (
    <>
      {input.assertions.map((assertion) => (
        <IssuedBadgeRow
          assertion={assertion}
          showNotificationRetry={input.showNotificationRetry}
          learnerReturnHref={input.learnerReturnHref}
          evidenceHref={input.evidenceHrefForAssertion(assertion.assertionId)}
          statusHref={input.statusHrefForAssertion(assertion.assertionId)}
        />
      ))}
    </>
  );
};
