import type { PropsWithChildren } from "hono/jsx";
import { type CtDataAttributes, type HonoElement, normalizedClassName } from "./jsx-utils";

export type { CtDataAttributes } from "./jsx-utils";

export type CtActionVariant = "primary" | "secondary" | "quiet" | "danger";
export type CtActionSize = "sm" | "md" | "lg" | "compact";
export type CtButtonType = "button" | "submit" | "reset";

export interface CtActionClassInput {
  variant?: CtActionVariant | undefined;
  size?: CtActionSize | undefined;
  text?: boolean | undefined;
  className?: string | undefined;
}

export const ctActionClass = (input: CtActionClassInput = {}): string => {
  const variant = input.variant ?? "primary";
  const size = input.size ?? "md";
  const classes = ["ct-action", `ct-action--${variant}`, `ct-action--${size}`];

  if (input.text === true) {
    classes.push("ct-action--text");
  }

  const extraClass = normalizedClassName(input.className);

  if (extraClass !== undefined) {
    classes.unshift(extraClass);
  }

  return classes.join(" ");
};

export const CtButton = ({
  id,
  type = "button",
  variant,
  size,
  disabled,
  hidden,
  form,
  formAction,
  name,
  value,
  className,
  ariaLabel,
  ariaControls,
  ariaExpanded,
  dataAttributes,
  children,
}: PropsWithChildren<{
  id?: string | undefined;
  type?: CtButtonType | undefined;
  variant?: CtActionVariant | undefined;
  size?: CtActionSize | undefined;
  disabled?: boolean | undefined;
  hidden?: boolean | undefined;
  form?: string | undefined;
  formAction?: string | undefined;
  name?: string | undefined;
  value?: string | undefined;
  className?: string | undefined;
  ariaLabel?: string | undefined;
  ariaControls?: string | undefined;
  ariaExpanded?: boolean | undefined;
  dataAttributes?: CtDataAttributes | undefined;
}>): HonoElement => {
  return (
    <button
      id={id}
      type={type}
      form={form}
      formaction={formAction}
      name={name}
      value={value}
      class={ctActionClass({ variant, size, className })}
      disabled={disabled}
      hidden={hidden}
      aria-label={ariaLabel}
      aria-controls={ariaControls}
      aria-expanded={ariaExpanded === undefined ? undefined : ariaExpanded ? "true" : "false"}
      {...(dataAttributes ?? {})}
    >
      {children}
    </button>
  );
};

export const CtButtonLink = ({
  href,
  variant,
  size,
  target,
  rel,
  hidden,
  className,
  ariaLabel,
  dataAttributes,
  children,
}: PropsWithChildren<{
  href: string;
  variant?: CtActionVariant | undefined;
  size?: CtActionSize | undefined;
  target?: "_blank" | undefined;
  rel?: string | undefined;
  hidden?: boolean | undefined;
  className?: string | undefined;
  ariaLabel?: string | undefined;
  dataAttributes?: CtDataAttributes | undefined;
}>): HonoElement => {
  return (
    <a
      class={ctActionClass({ variant, size, className })}
      href={href}
      target={target}
      rel={rel}
      aria-label={ariaLabel}
      hidden={hidden}
      {...(dataAttributes ?? {})}
    >
      {children}
    </a>
  );
};

export const CtTextButton = ({
  id,
  type = "button",
  disabled,
  hidden,
  className,
  ariaLabel,
  dataAttributes,
  children,
}: PropsWithChildren<{
  id?: string | undefined;
  type?: CtButtonType | undefined;
  disabled?: boolean | undefined;
  hidden?: boolean | undefined;
  className?: string | undefined;
  ariaLabel?: string | undefined;
  dataAttributes?: CtDataAttributes | undefined;
}>): HonoElement => {
  const actionClass = ctActionClass({
    variant: "quiet",
    size: "compact",
    text: true,
    className,
  });

  return (
    <button
      id={id}
      class={actionClass}
      type={type}
      disabled={disabled}
      hidden={hidden}
      aria-label={ariaLabel}
      {...(dataAttributes ?? {})}
    >
      {children}
    </button>
  );
};

export const CtTextLink = ({
  id,
  href,
  target,
  rel,
  hidden,
  className,
  ariaLabel,
  dataAttributes,
  children,
}: PropsWithChildren<{
  id?: string | undefined;
  href: string;
  target?: "_blank" | undefined;
  rel?: string | undefined;
  hidden?: boolean | undefined;
  className?: string | undefined;
  ariaLabel?: string | undefined;
  dataAttributes?: CtDataAttributes | undefined;
}>): HonoElement => {
  return (
    <a
      id={id}
      class={ctActionClass({
        variant: "quiet",
        size: "compact",
        text: true,
        className,
      })}
      href={href}
      target={target}
      rel={rel}
      hidden={hidden}
      aria-label={ariaLabel}
      {...(dataAttributes ?? {})}
    >
      {children}
    </a>
  );
};

export const CtActionGroup = ({
  ariaLabel,
  className,
  children,
}: PropsWithChildren<{
  ariaLabel?: string | undefined;
  className?: string | undefined;
}>): HonoElement => {
  const extraClass = normalizedClassName(className);
  const classes = extraClass === undefined ? "ct-action-group" : `${extraClass} ct-action-group`;

  return (
    <div
      class={classes}
      role={ariaLabel === undefined ? undefined : "group"}
      aria-label={ariaLabel}
    >
      {children}
    </div>
  );
};
