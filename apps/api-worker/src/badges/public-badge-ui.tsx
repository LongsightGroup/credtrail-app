import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";

export type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export type PublicBadgeButtonVariant = "primary" | "secondary";

const publicBadgeButtonClass = (variant: PublicBadgeButtonVariant = "secondary"): string => {
  return variant === "primary"
    ? "public-badge__button public-badge__button--primary"
    : "public-badge__button";
};

export const PublicBadgeButtonLink = ({
  href,
  variant,
  target,
  rel,
  children,
}: PropsWithChildren<{
  href: string;
  variant?: PublicBadgeButtonVariant;
  target?: "_blank";
  rel?: string;
}>): HonoElement => {
  return (
    <a class={publicBadgeButtonClass(variant)} href={href} target={target} rel={rel}>
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
    <button class="badge-wall__button" type="button" data-copy-value={input.value}>
      Copy link
    </button>
  );
};
