import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import { CtButton } from "../ui/actions";
import type { LtiBadgeSummaryCard, LtiBadgeSummaryStatus } from "./view-models";

export type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export const LtiLaunchCard = ({
  stack,
  children,
}: PropsWithChildren<{
  stack?: boolean;
}>): HonoElement => {
  const className =
    stack === true ? "lti-launch__card lti-launch__card--stack" : "lti-launch__card";

  return <article class={className}>{children}</article>;
};

export const LtiSubmitButton = ({
  disabled,
  children,
}: PropsWithChildren<{
  disabled?: boolean;
}>): HonoElement => {
  return (
    <CtButton type="submit" disabled={disabled === true}>
      {children}
    </CtButton>
  );
};

export const DetailRows = (input: {
  rows: readonly {
    label: string;
    value: string | number;
  }[];
}): HonoElement => {
  return (
    <>
      {input.rows.map((row) => (
        <>
          <dt>{row.label}</dt>
          <dd>{String(row.value)}</dd>
        </>
      ))}
    </>
  );
};

const ltiBadgeInitials = (title: string): string => {
  const initials = title
    .trim()
    .split(/\s+/)
    .slice(0, 2)
    .map((word) => word.charAt(0).toUpperCase())
    .join("");

  return initials.length > 0 ? initials : "B";
};

export const BadgeSummaryContent = (input: {
  badge: LtiBadgeSummaryCard;
  heading: "h3" | "h4";
  headingId?: string;
  srOnlySuffix: string;
  imageLoading?: "lazy";
  status: LtiBadgeSummaryStatus;
  footer?: HonoElement | null;
}): HonoElement => {
  const headingContent = (
    <a href={input.badge.criteriaPath} target="_blank" rel="noopener noreferrer">
      {input.badge.title}
      <span class="lti-launch__sr-only"> {input.srOnlySuffix}</span>
    </a>
  );

  return (
    <>
      <div class="lti-launch__badge-summary-media" aria-hidden={input.badge.imageUri === null}>
        {input.badge.imageUri === null ? (
          <span class="lti-launch__badge-placeholder">{ltiBadgeInitials(input.badge.title)}</span>
        ) : (
          <img
            class="lti-launch__badge-summary-image"
            src={input.badge.imageUri}
            alt={`${input.badge.title} badge artwork`}
            width={72}
            height={72}
            decoding="async"
            loading={input.imageLoading}
          />
        )}
      </div>
      <div class="lti-launch__badge-summary-copy">
        <div class="lti-launch__badge-summary-title-row">
          {input.heading === "h3" ? (
            <h3 id={input.headingId}>{headingContent}</h3>
          ) : (
            <h4>{headingContent}</h4>
          )}
          <span class={`lti-launch__status-pill lti-launch__status-pill--${input.status.modifier}`}>
            {input.status.label}
          </span>
        </div>
        <p>{input.badge.summary}</p>
        {input.footer ?? null}
      </div>
    </>
  );
};
