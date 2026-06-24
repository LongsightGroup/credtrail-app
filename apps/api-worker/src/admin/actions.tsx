import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import {
  CtActionGroup,
  CtButton,
  CtButtonLink,
  type CtActionSize,
  type CtDataAttributes,
  type CtLegacyActionVariant,
  ctActionVariantFromLegacy,
} from "../ui/actions";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export type AdminButtonVariant = Extract<
  CtLegacyActionVariant,
  "primary" | "secondary" | "ghost" | "danger"
>;
export type AdminButtonSize = "default" | "tiny";

type ButtonType = "button" | "submit" | "reset";
type DataAttributes = CtDataAttributes;

export const adminButtonClass = (input?: { extraClass?: string | undefined }): string => {
  const classNames = ["ct-admin__button"];

  if (input?.extraClass !== undefined && input.extraClass.trim().length > 0) {
    classNames.push(input.extraClass.trim());
  }

  return classNames.join(" ");
};

const adminButtonSizeToCtSize = (size: AdminButtonSize | undefined): CtActionSize => {
  return size === "tiny" ? "sm" : "md";
};

const normalizedExtraClass = (className: string | undefined): string | undefined => {
  const normalizedClassName = className?.trim();

  return normalizedClassName === undefined || normalizedClassName.length === 0
    ? undefined
    : normalizedClassName;
};

export const AdminButton = ({
  id,
  type = "button",
  variant,
  size,
  disabled,
  hidden,
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
  hidden?: boolean;
  form?: string;
  formAction?: string;
  className?: string;
  ariaLabel?: string;
  dataAttributes?: DataAttributes;
}>): HonoElement => {
  return (
    <CtButton
      id={id}
      type={type}
      form={form}
      formAction={formAction}
      variant={ctActionVariantFromLegacy(variant)}
      size={adminButtonSizeToCtSize(size)}
      className={adminButtonClass({ extraClass: className })}
      disabled={disabled}
      hidden={hidden}
      ariaLabel={ariaLabel}
      dataAttributes={dataAttributes}
    >
      {children}
    </CtButton>
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
    <CtButtonLink
      href={href}
      variant={ctActionVariantFromLegacy(variant, "secondary")}
      size={adminButtonSizeToCtSize(size)}
      target={target}
      rel={rel}
      className={adminButtonClass({ extraClass: className })}
      ariaLabel={ariaLabel}
      dataAttributes={dataAttributes}
    >
      {children}
    </CtButtonLink>
  );
};

export const AdminActions = ({
  align = "start",
  className,
  children,
}: PropsWithChildren<{
  align?: "start" | "end";
  className?: string;
}>): HonoElement => {
  const classNames: string[] = [];

  if (align === "end") {
    classNames.push("ct-admin__actions--end");
  }

  const extraClass = normalizedExtraClass(className);

  if (extraClass !== undefined) {
    classNames.push(extraClass);
  }

  return (
    <CtActionGroup className={classNames.length === 0 ? undefined : classNames.join(" ")}>
      {children}
    </CtActionGroup>
  );
};
