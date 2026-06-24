import type { PropsWithChildren, Child } from "hono/jsx";
import {
  classNames,
  describedByValue,
  type CtDataAttributes,
  type HonoElement,
  type HonoFragmentChildren,
  normalizedClassName,
} from "./jsx-utils";

export type CtFormMethod = "get" | "post";
export type CtInputType =
  | "text"
  | "email"
  | "password"
  | "url"
  | "search"
  | "number"
  | "tel"
  | "date"
  | "datetime-local"
  | "file"
  | "hidden";
export type CtTextareaVariant = "default" | "prose" | "code";
export type CtCheckboxType = "checkbox" | "radio";

const controlClassNames = (
  className: string | undefined,
  ...controlClasses: string[]
): string | undefined => {
  const normalized = normalizedClassName(className);

  if (controlClasses.length === 0) {
    return normalized;
  }

  return classNames(normalized, ...controlClasses);
};

export const CtForm = ({
  id,
  method,
  action,
  encType,
  className,
  dataAttributes,
  hidden,
  children,
}: PropsWithChildren<{
  id?: string | undefined;
  method?: CtFormMethod | undefined;
  action?: string | undefined;
  encType?: "multipart/form-data" | undefined;
  className?: string | undefined;
  dataAttributes?: CtDataAttributes | undefined;
  hidden?: boolean | undefined;
}>): HonoElement => {
  return (
    <form
      id={id}
      method={method}
      action={action}
      enctype={encType}
      class={classNames(normalizedClassName(className), "ct-form")}
      hidden={hidden}
      {...(dataAttributes ?? {})}
    >
      {children}
    </form>
  );
};

export const CtFieldHint = ({
  id,
  className,
  children,
}: PropsWithChildren<{
  id?: string | undefined;
  className?: string | undefined;
}>): HonoElement => {
  return (
    <span id={id} class={classNames(normalizedClassName(className), "ct-field__hint")}>
      {children}
    </span>
  );
};

export const CtFieldError = ({
  id,
  className,
  children,
}: PropsWithChildren<{
  id?: string | undefined;
  className?: string | undefined;
}>): HonoElement => {
  return (
    <span id={id} class={classNames(normalizedClassName(className), "ct-field__error")}>
      {children}
    </span>
  );
};

export const CtField = ({
  id,
  label,
  inline,
  compact,
  className,
  children,
}: PropsWithChildren<{
  id?: string | undefined;
  label: string;
  inline?: boolean | undefined;
  compact?: boolean | undefined;
  className?: string | undefined;
}>): HonoElement => {
  return (
    <label
      id={id}
      class={classNames(
        normalizedClassName(className),
        "ct-field",
        inline === true ? "ct-field--inline" : undefined,
        compact === true ? "ct-field--compact" : undefined,
      )}
    >
      <span class="ct-field__label">{label}</span>
      {children}
    </label>
  );
};

export const CtInput = ({
  id,
  name,
  type = "text",
  value,
  placeholder,
  required,
  disabled,
  readonly,
  hidden,
  autocomplete,
  minlength,
  maxlength,
  pattern,
  form,
  min,
  max,
  step,
  accept,
  inputmode,
  className,
  ariaLabel,
  describedBy,
  dataAttributes,
}: {
  id?: string | undefined;
  name?: string | undefined;
  type?: CtInputType | undefined;
  value?: string | undefined;
  placeholder?: string | undefined;
  required?: boolean | undefined;
  disabled?: boolean | undefined;
  readonly?: boolean | undefined;
  hidden?: boolean | undefined;
  autocomplete?: string | undefined;
  minlength?: number | undefined;
  maxlength?: number | undefined;
  pattern?: string | undefined;
  form?: string | undefined;
  min?: string | undefined;
  max?: string | undefined;
  step?: string | undefined;
  accept?: string | undefined;
  inputmode?:
    | "none"
    | "text"
    | "decimal"
    | "numeric"
    | "tel"
    | "search"
    | "email"
    | "url"
    | undefined;
  className?: string | undefined;
  ariaLabel?: string | undefined;
  describedBy?: string | readonly string[] | undefined;
  dataAttributes?: CtDataAttributes | undefined;
}): HonoElement => {
  const inputClass =
    type === "hidden"
      ? normalizedClassName(className)
      : controlClassNames(className, "ct-input", "ct-field__control");

  return (
    <input
      id={id}
      name={name}
      type={type}
      value={value}
      placeholder={placeholder}
      required={required}
      disabled={disabled}
      readonly={readonly}
      hidden={hidden}
      autocomplete={autocomplete}
      minlength={minlength}
      maxlength={maxlength}
      pattern={pattern}
      form={form}
      min={min}
      max={max}
      step={step}
      accept={accept}
      inputmode={inputmode}
      class={inputClass}
      aria-label={ariaLabel}
      aria-describedby={describedByValue(describedBy)}
      {...(dataAttributes ?? {})}
    />
  );
};

export const CtTextarea = ({
  id,
  name,
  value,
  placeholder,
  required,
  disabled,
  readonly,
  hidden,
  autocomplete,
  minlength,
  maxlength,
  rows,
  form,
  variant = "default",
  className,
  ariaLabel,
  describedBy,
  dataAttributes,
}: {
  id?: string | undefined;
  name?: string | undefined;
  value?: string | undefined;
  placeholder?: string | undefined;
  required?: boolean | undefined;
  disabled?: boolean | undefined;
  readonly?: boolean | undefined;
  hidden?: boolean | undefined;
  autocomplete?: string | undefined;
  minlength?: number | undefined;
  maxlength?: number | undefined;
  rows?: number | undefined;
  form?: string | undefined;
  variant?: CtTextareaVariant | undefined;
  className?: string | undefined;
  ariaLabel?: string | undefined;
  describedBy?: string | readonly string[] | undefined;
  dataAttributes?: CtDataAttributes | undefined;
}): HonoElement => {
  return (
    <textarea
      id={id}
      name={name}
      placeholder={placeholder}
      required={required}
      disabled={disabled}
      readonly={readonly}
      hidden={hidden}
      autocomplete={autocomplete}
      minlength={minlength}
      maxlength={maxlength}
      rows={rows}
      form={form}
      class={classNames(
        normalizedClassName(className),
        "ct-textarea",
        "ct-field__control",
        variant === "prose" ? "ct-textarea--prose" : undefined,
        variant === "code" ? "ct-textarea--code" : undefined,
      )}
      aria-label={ariaLabel}
      aria-describedby={describedByValue(describedBy)}
      {...(dataAttributes ?? {})}
    >
      {value}
    </textarea>
  );
};

export type CtSelectChildren = Child | readonly Child[] | HonoFragmentChildren;

export const CtSelect = ({
  id,
  name,
  required,
  disabled,
  hidden,
  multiple,
  size,
  form,
  className,
  ariaLabel,
  describedBy,
  onchange,
  dataAttributes,
  children,
}: {
  id?: string | undefined;
  name?: string | undefined;
  required?: boolean | undefined;
  disabled?: boolean | undefined;
  hidden?: boolean | undefined;
  multiple?: boolean | undefined;
  size?: number | undefined;
  form?: string | undefined;
  className?: string | undefined;
  ariaLabel?: string | undefined;
  describedBy?: string | readonly string[] | undefined;
  onchange?: string | undefined;
  dataAttributes?: CtDataAttributes | undefined;
  children?: CtSelectChildren;
}): HonoElement => {
  return (
    <select
      id={id}
      name={name}
      required={required}
      disabled={disabled}
      hidden={hidden}
      multiple={multiple}
      size={size}
      form={form}
      class={controlClassNames(className, "ct-select", "ct-field__control")}
      aria-label={ariaLabel}
      aria-describedby={describedByValue(describedBy)}
      onchange={onchange}
      {...(dataAttributes ?? {})}
    >
      {children}
    </select>
  );
};

export const CtCheckboxControl = ({
  id,
  name,
  type = "checkbox",
  value,
  checked,
  required,
  disabled,
  form,
  className,
  ariaLabel,
  describedBy,
  dataAttributes,
}: {
  id?: string | undefined;
  name: string;
  type?: CtCheckboxType | undefined;
  value?: string | undefined;
  checked?: boolean | undefined;
  required?: boolean | undefined;
  disabled?: boolean | undefined;
  form?: string | undefined;
  className?: string | undefined;
  ariaLabel?: string | undefined;
  describedBy?: string | readonly string[] | undefined;
  dataAttributes?: CtDataAttributes | undefined;
}): HonoElement => {
  return (
    <input
      id={id}
      name={name}
      type={type}
      value={value}
      checked={checked}
      required={required}
      disabled={disabled}
      form={form}
      class={controlClassNames(className, "ct-checkbox-field__control")}
      aria-label={ariaLabel}
      aria-describedby={describedByValue(describedBy)}
      {...(dataAttributes ?? {})}
    />
  );
};

export const CtCheckboxField = ({
  id,
  name,
  type = "checkbox",
  value,
  label,
  checked,
  required,
  disabled,
  hidden,
  form,
  className,
  ariaLabel,
  describedBy,
  dataAttributes,
}: {
  id?: string | undefined;
  name: string;
  type?: CtCheckboxType | undefined;
  value?: string | undefined;
  label: string;
  checked?: boolean | undefined;
  required?: boolean | undefined;
  disabled?: boolean | undefined;
  hidden?: boolean | undefined;
  form?: string | undefined;
  className?: string | undefined;
  ariaLabel?: string | undefined;
  describedBy?: string | readonly string[] | undefined;
  dataAttributes?: CtDataAttributes | undefined;
}): HonoElement => {
  return (
    <label class={classNames(normalizedClassName(className), "ct-checkbox-field")} hidden={hidden}>
      <CtCheckboxControl
        id={id}
        name={name}
        type={type}
        value={value}
        checked={checked}
        required={required}
        disabled={disabled}
        form={form}
        ariaLabel={ariaLabel}
        describedBy={describedBy}
        dataAttributes={dataAttributes}
      />
      <span class="ct-checkbox-field__label">{label}</span>
    </label>
  );
};
