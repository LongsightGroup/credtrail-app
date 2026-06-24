import type { HtmlEscapedString } from "hono/utils/html";

export type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export type HonoFragmentChildren =
  | HtmlEscapedString
  | Promise<HtmlEscapedString>
  | readonly HonoFragmentChildren[];

export type CtDataAttributes = Partial<Record<`data-${string}`, string>>;

export const normalizedClassName = (className: string | undefined): string | undefined => {
  const normalized = className?.trim();

  return normalized === undefined || normalized.length === 0 ? undefined : normalized;
};

export const classNames = (...entries: Array<string | undefined>): string => {
  return entries.filter((entry) => entry !== undefined && entry.length > 0).join(" ");
};

export const describedByValue = (
  describedBy: string | readonly string[] | undefined,
): string | undefined => {
  if (describedBy === undefined) {
    return undefined;
  }

  if (typeof describedBy !== "string") {
    const ids = describedBy.map((entry) => entry.trim()).filter((entry) => entry.length > 0);

    return ids.length === 0 ? undefined : ids.join(" ");
  }

  const normalized = describedBy.trim();

  return normalized.length === 0 ? undefined : normalized;
};
