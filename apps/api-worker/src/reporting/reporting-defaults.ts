import type { TenantReportingOverviewQuery } from "@credtrail/validation";

export const REPORTING_DEFAULT_WINDOW_DAYS = 90;

const subtractUtcDays = (isoDate: string, days: number): string => {
  const date = new Date(`${isoDate}T00:00:00.000Z`);
  date.setUTCDate(date.getUTCDate() - days);
  return date.toISOString().slice(0, 10);
};

export const currentUtcDateKey = (): string => {
  return new Date().toISOString().slice(0, 10);
};

export const resolveReportingDefaultWindow = (input?: {
  today?: string | undefined;
}): {
  issuedFrom: string;
  issuedTo: string;
} => {
  const issuedTo = input?.today ?? currentUtcDateKey();

  return {
    issuedFrom: subtractUtcDays(issuedTo, REPORTING_DEFAULT_WINDOW_DAYS - 1),
    issuedTo,
  };
};

export const applySmartReportingDefaults = (input: {
  query: TenantReportingOverviewQuery;
  today?: string | undefined;
}): TenantReportingOverviewQuery => {
  if (input.query.issuedFrom !== undefined || input.query.issuedTo !== undefined) {
    return input.query;
  }

  return {
    ...input.query,
    ...resolveReportingDefaultWindow({ today: input.today }),
  };
};
