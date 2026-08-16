import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import type { BadgeIssuanceRuleValueListRecord, TenantAssertionSummaryRecord } from "@credtrail/db";
import type { BadgeRuleReviewQueueEntryView } from "../badge-rule-review-queue-workspace";
import { formatBadgeRuleReviewQueueSummary } from "../badge-rule-review-queue-workspace";
import type { CtDataAttributes } from "../ui/jsx-utils";
import { CtCheckboxField, CtField, CtForm, CtInput, type CtCheckboxType } from "../ui/forms";
import { AdminButton, AdminButtonLink, type AdminButtonVariant } from "./actions";
import {
  formatRuleValueListKind,
  formatRuleValueListValuesSummary,
} from "./rule-value-lists-presentation";
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
              const ariaSort = typeof header === "string" ? undefined : header.ariaSort;

              return (
                <th scope={scope} aria-sort={ariaSort}>
                  {label}
                </th>
              );
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
  dataAttributes,
}: {
  name: string;
  label: string;
  value?: string;
  checked?: boolean;
  type?: CtCheckboxType;
  disabled?: boolean;
  form?: string;
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

export const AdminStatus = ({
  id,
  tone,
  children,
}: PropsWithChildren<{
  id?: string;
  tone?: "info" | "success" | "warning" | "error";
}>): HonoElement => {
  return (
    <p id={id} class="ct-admin__status" data-tone={tone}>
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
  revokeLifecycleHref: string;
  canRevoke: boolean;
}): HonoElement => {
  return (
    <AdminActionBar ariaLabel={`Actions for assertion ${input.assertionId}`}>
      <AdminButtonLink
        href={input.viewBadgeHref}
        variant="primary"
        size="tiny"
        target="_blank"
        rel="noopener noreferrer"
      >
        Open
      </AdminButtonLink>
      <AdminButtonLink href={input.evidenceHref} size="tiny" variant="secondary">
        Evidence
      </AdminButtonLink>
      <AdminActionMenu
        menuId={`issued-badge-action-menu-${input.assertionId}`}
        ariaLabel={`More actions for assertion ${input.assertionId}`}
      >
        <AdminActionMenuLink href={input.rawJsonHref} target="_blank" rel="noopener noreferrer">
          Open JSON-LD
        </AdminActionMenuLink>
        {input.canRevoke ? (
          <AdminActionMenuLink href={input.revokeLifecycleHref}>Revoke badge</AdminActionMenuLink>
        ) : null}
      </AdminActionMenu>
    </AdminActionBar>
  );
};

const IssuedBadgeRow = (input: {
  assertion: TenantAssertionSummaryRecord;
  evidenceHref: string;
  revokeLifecycleHref: string;
}): HonoElement => {
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
            evidenceHref={input.evidenceHref}
            revokeLifecycleHref={input.revokeLifecycleHref}
            canRevoke={assertion.state !== "revoked"}
          />
        </div>
      </td>
    </tr>
  );
};

const RuleValueListRow = (input: { valueList: BadgeIssuanceRuleValueListRecord }): HonoElement => {
  const valueList = input.valueList;
  const valueSummary = formatRuleValueListValuesSummary(valueList.values);

  return (
    <tr data-rule-value-list-row="true">
      <td>
        <strong>{valueList.label}</strong>
        <AdminMeta>{valueList.id}</AdminMeta>
      </td>
      <td>{formatRuleValueListKind(valueList.kind)}</td>
      <td>
        {valueSummary}
        <AdminMeta>
          {String(valueList.values.length)} value{valueList.values.length === 1 ? "" : "s"}
        </AdminMeta>
      </td>
    </tr>
  );
};

export const RuleValueListRows = (input: {
  valueLists: readonly BadgeIssuanceRuleValueListRecord[];
  emptyMessage?: string;
}): HonoElement => {
  if (input.valueLists.length === 0) {
    return (
      <AdminEmptyTableRow colSpan={3}>
        {input.emptyMessage ?? "No reusable value lists yet."}
      </AdminEmptyTableRow>
    );
  }

  return (
    <>
      {input.valueLists.map((valueList) => (
        <RuleValueListRow valueList={valueList} />
      ))}
    </>
  );
};

const ReviewQueueRow = (input: {
  entry: BadgeRuleReviewQueueEntryView;
  resolveActionPath: string;
}): HonoElement => {
  const entry = input.entry;
  const ruleLabel = entry.ruleName ?? entry.ruleId;
  const summaryText = formatBadgeRuleReviewQueueSummary(entry.evaluationSummary);
  const isPending = entry.reviewStatus === "pending";

  return (
    <tr data-review-queue-row="true">
      <td>{formatIsoTimestamp(entry.evaluatedAt)}</td>
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
          <div class="ct-admin__issued-actions ct-cluster">
            <AdminForm method="post" action={input.resolveActionPath}>
              <CtInput type="hidden" name="evaluationId" value={entry.evaluationId} />
              <CtInput type="hidden" name="decision" value="issue" />
              <CtInput type="hidden" name="comment" value="Manual review approved by issuer" />
              <AdminButton type="submit" size="tiny" variant="secondary">
                Issue
              </AdminButton>
            </AdminForm>
            <AdminForm method="post" action={input.resolveActionPath}>
              <CtInput type="hidden" name="evaluationId" value={entry.evaluationId} />
              <CtInput type="hidden" name="decision" value="dismiss" />
              <CtInput type="hidden" name="comment" value="Missing facts confirmed; no issue" />
              <AdminButton type="submit" size="tiny" variant="quiet">
                Dismiss
              </AdminButton>
            </AdminForm>
          </div>
        ) : (
          <AdminMeta>Resolved</AdminMeta>
        )}
      </td>
    </tr>
  );
};

export const ReviewQueueRows = (input: {
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
        <ReviewQueueRow entry={entry} resolveActionPath={input.resolveActionPath} />
      ))}
    </>
  );
};

export const IssuedBadgeRows = (input: {
  assertions: readonly TenantAssertionSummaryRecord[];
  evidenceHrefForAssertion: (assertionId: string) => string;
  revokeLifecycleHrefForAssertion: (assertionId: string) => string;
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
        <IssuedBadgeRow
          assertion={assertion}
          evidenceHref={input.evidenceHrefForAssertion(assertion.assertionId)}
          revokeLifecycleHref={input.revokeLifecycleHrefForAssertion(assertion.assertionId)}
        />
      ))}
    </>
  );
};
