import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import type { TenantAssertionSummaryRecord } from "@credtrail/db";
import { formatIsoTimestamp } from "../utils/display-format";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export type AdminButtonVariant = "primary" | "secondary" | "ghost" | "danger";
export type AdminButtonSize = "default" | "tiny";

type ButtonType = "button" | "submit" | "reset";
type DataAttributes = Partial<Record<`data-${string}`, string>>;

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
  className?: string;
  ariaLabel?: string;
  dataAttributes?: DataAttributes;
}>): HonoElement => {
  return (
    <button
      id={id}
      type={type}
      form={form}
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
        <div class="ct-admin__meta">{assertion.badgeTemplateId}</div>
      </td>
      <td>
        <span class={`ct-admin__status-pill ct-admin__status-pill--${assertion.state}`}>
          {assertion.state}
        </span>
        <div class="ct-admin__meta">{assertion.source}</div>
      </td>
      <td>
        <div class="ct-admin__assertion-id">{assertion.assertionId}</div>
        {assertion.publicId === null ? null : (
          <div class="ct-admin__meta">public: {assertion.publicId}</div>
        )}
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
      <tr>
        <td colspan={6} class="ct-admin__empty">
          {input.emptyMessage ?? "No assertions matched the selected filters."}
        </td>
      </tr>
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
