import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

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
  | "file";
export type CtTextareaVariant = "default" | "prose" | "code";
export type CtCheckboxType = "checkbox" | "radio";
export type CtDataAttributes = Partial<Record<`data-${string}`, string>>;

const normalizedClassName = (className: string | undefined): string | undefined => {
  const normalized = className?.trim();

  return normalized === undefined || normalized.length === 0 ? undefined : normalized;
};

const classNames = (...entries: Array<string | undefined>): string => {
  return entries.filter((entry) => entry !== undefined && entry.length > 0).join(" ");
};

const describedByValue = (
  describedBy: string | readonly string[] | undefined,
): string | undefined => {
  if (describedBy === undefined) {
    return undefined;
  }

  if (typeof describedBy !== "string") {
    const ids = describedBy.map((entry) => entry.trim()).filter((entry) => entry.length > 0);

    return ids.length === 0 ? undefined : ids.join(" ");
  }

  const normalized = describedBy?.trim();

  return normalized === undefined || normalized.length === 0 ? undefined : normalized;
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
  htmlFor,
  hint,
  hintId,
  error,
  errorId,
  inline,
  compact,
  className,
  children,
}: PropsWithChildren<{
  id?: string | undefined;
  label: string;
  htmlFor?: string | undefined;
  hint?: string | undefined;
  hintId?: string | undefined;
  error?: string | undefined;
  errorId?: string | undefined;
  inline?: boolean | undefined;
  compact?: boolean | undefined;
  className?: string | undefined;
}>): HonoElement => {
  const fieldClass = classNames(
    normalizedClassName(className),
    "ct-field",
    inline === true ? "ct-field--inline" : undefined,
    compact === true ? "ct-field--compact" : undefined,
  );
  const labelContent = <span class="ct-field__label">{label}</span>;
  const hintContent = hint === undefined ? null : <CtFieldHint id={hintId}>{hint}</CtFieldHint>;
  const errorContent =
    error === undefined ? null : <CtFieldError id={errorId}>{error}</CtFieldError>;

  if (htmlFor !== undefined) {
    return (
      <div id={id} class={fieldClass}>
        <label class="ct-field__label" for={htmlFor}>
          {label}
        </label>
        {hintContent}
        {children}
        {errorContent}
      </div>
    );
  }

  return (
    <label id={id} class={fieldClass}>
      {labelContent}
      {hintContent}
      {children}
      {errorContent}
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
      class={classNames(normalizedClassName(className), "ct-input", "ct-field__control")}
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
  dataAttributes,
  children,
}: PropsWithChildren<{
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
  dataAttributes?: CtDataAttributes | undefined;
}>): HonoElement => {
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
      class={classNames(normalizedClassName(className), "ct-select", "ct-field__control")}
      aria-label={ariaLabel}
      aria-describedby={describedByValue(describedBy)}
      {...(dataAttributes ?? {})}
    >
      {children}
    </select>
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
  className,
  ariaLabel,
  describedBy,
  dataAttributes,
  children,
}: PropsWithChildren<{
  id?: string | undefined;
  name?: string | undefined;
  type?: CtCheckboxType | undefined;
  value?: string | undefined;
  label?: string | undefined;
  checked?: boolean | undefined;
  required?: boolean | undefined;
  disabled?: boolean | undefined;
  hidden?: boolean | undefined;
  className?: string | undefined;
  ariaLabel?: string | undefined;
  describedBy?: string | readonly string[] | undefined;
  dataAttributes?: CtDataAttributes | undefined;
}>): HonoElement => {
  if (name === undefined && label === undefined && children !== undefined) {
    return (
      <label
        class={classNames(normalizedClassName(className), "ct-checkbox-field")}
        hidden={hidden}
      >
        {children}
      </label>
    );
  }

  return (
    <label class={classNames(normalizedClassName(className), "ct-checkbox-field")} hidden={hidden}>
      <input
        id={id}
        name={name}
        type={type}
        value={value}
        checked={checked}
        required={required}
        disabled={disabled}
        class="ct-checkbox-field__control"
        aria-label={ariaLabel}
        aria-describedby={describedByValue(describedBy)}
        {...(dataAttributes ?? {})}
      />
      <span class="ct-checkbox-field__label">{label ?? children}</span>
    </label>
  );
};
