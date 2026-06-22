import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";

export type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export type PublicBadgeButtonVariant = "primary" | "secondary";

const publicBadgeButtonClass = (variant: PublicBadgeButtonVariant = "secondary"): string => {
  return variant === "primary"
    ? "public-badge__button public-badge__button--primary"
    : "public-badge__button";
};

const joinClassNames = (...classNames: Array<string | undefined>): string => {
  return classNames
    .filter((className) => className !== undefined && className.length > 0)
    .join(" ");
};

const PublicBadgeCopyIconGraphic = (input: { class: string }): HonoElement => {
  return (
    <svg class={input.class} aria-hidden="true" focusable="false" viewBox="0 0 16 16">
      <rect
        x="4.25"
        y="4.25"
        width="8.5"
        height="9.5"
        rx="1.25"
        fill="none"
        stroke="currentColor"
      />
      <path
        d="M5.75 2.75h5.5a1.25 1.25 0 0 1 1.25 1.25v1"
        fill="none"
        stroke="currentColor"
        stroke-linecap="round"
      />
    </svg>
  );
};

export const PublicBadgeButtonLink = ({
  href,
  variant,
  class: className,
  target,
  rel,
  children,
}: PropsWithChildren<{
  href: string;
  variant?: PublicBadgeButtonVariant;
  class?: string;
  target?: "_blank";
  rel?: string;
}>): HonoElement => {
  return (
    <a
      class={joinClassNames(publicBadgeButtonClass(variant), className)}
      href={href}
      target={target}
      rel={rel}
    >
      {children}
    </a>
  );
};

export const PublicBadgeButton = ({
  id,
  type = "button",
  variant,
  dataCopyValue,
  dataCredentialJsonUrl,
  hidden,
  children,
}: PropsWithChildren<{
  id?: string;
  type?: "button" | "submit";
  variant?: PublicBadgeButtonVariant;
  dataCopyValue?: string;
  dataCredentialJsonUrl?: string;
  hidden?: boolean;
}>): HonoElement => {
  return (
    <button
      id={id}
      class={publicBadgeButtonClass(variant)}
      type={type}
      data-copy-value={dataCopyValue}
      data-credential-json-url={dataCredentialJsonUrl}
      hidden={hidden}
    >
      {children}
    </button>
  );
};

export const PublicBadgeTextLink = ({
  href,
  target,
  rel,
  children,
}: PropsWithChildren<{
  href: string;
  target?: "_blank";
  rel?: string;
}>): HonoElement => {
  return (
    <a class="public-badge__text-link" href={href} target={target} rel={rel}>
      {children}
    </a>
  );
};

export const PublicBadgeTextButton = ({
  id,
  type = "button",
  dataCopyValue,
  dataCredentialJsonUrl,
  hidden,
  children,
}: PropsWithChildren<{
  id?: string;
  type?: "button" | "submit";
  dataCopyValue?: string;
  dataCredentialJsonUrl?: string;
  hidden?: boolean;
}>): HonoElement => {
  return (
    <button
      id={id}
      class="public-badge__text-button"
      type={type}
      data-copy-value={dataCopyValue}
      data-credential-json-url={dataCredentialJsonUrl}
      hidden={hidden}
    >
      {children}
    </button>
  );
};

export const PublicBadgeCopyIconButton = ({
  id,
  ariaLabel,
  dataCopyValue,
}: {
  id?: string;
  ariaLabel: string;
  dataCopyValue: string;
}): HonoElement => {
  return (
    <button
      id={id}
      class="public-badge__icon-button"
      type="button"
      aria-label={ariaLabel}
      data-copy-value={dataCopyValue}
    >
      <PublicBadgeCopyIconGraphic class="public-badge__icon-button-graphic" />
    </button>
  );
};

export const BadgeWallButtonLink = ({
  href,
  variant,
  children,
}: PropsWithChildren<{
  href: string;
  variant?: PublicBadgeButtonVariant;
}>): HonoElement => {
  const className =
    variant === "primary" ? "badge-wall__button badge-wall__button--primary" : "badge-wall__button";

  return (
    <a class={className} href={href}>
      {children}
    </a>
  );
};

export const BadgeWallCopyButton = (input: { value: string }): HonoElement => {
  return (
    <button
      class="badge-wall__icon-button"
      type="button"
      aria-label="Copy link"
      data-copy-value={input.value}
    >
      <PublicBadgeCopyIconGraphic class="badge-wall__icon-button-graphic" />
    </button>
  );
};
