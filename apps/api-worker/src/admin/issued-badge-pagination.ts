import { z } from "zod";
import type { TenantAssertionSummaryRecord } from "@credtrail/db";

const cursorSchema = z.object({
  issuedAt: z.iso.datetime({ offset: true }),
  assertionId: z.string().min(1).max(256),
  direction: z.enum(["older", "newer"]),
});
export type IssuedBadgeCursor = z.infer<typeof cursorSchema>;

export const parseIssuedBadgeCursor = (value: string | undefined): IssuedBadgeCursor | undefined =>
  value ? cursorSchema.parse(JSON.parse(z.string().max(1024).parse(value))) : undefined;

export const paginateIssuedBadges = (
  rows: readonly TenantAssertionSummaryRecord[],
  limit: number,
  cursor: IssuedBadgeCursor | undefined,
): {
  assertions: TenantAssertionSummaryRecord[];
  olderCursor: string | null;
  newerCursor: string | null;
} => {
  const more = rows.length > limit;
  const assertions = rows.slice(0, limit);
  if (cursor?.direction === "newer") assertions.reverse();
  const first = assertions[0];
  const last = assertions.at(-1);
  const encode = (
    row: TenantAssertionSummaryRecord,
    direction: IssuedBadgeCursor["direction"],
  ): string => JSON.stringify({ issuedAt: row.issuedAt, assertionId: row.assertionId, direction });
  return {
    assertions,
    olderCursor: last && (cursor?.direction === "newer" || more) ? encode(last, "older") : null,
    newerCursor:
      first && (cursor?.direction === "older" || (cursor?.direction === "newer" && more))
        ? encode(first, "newer")
        : null,
  };
};
