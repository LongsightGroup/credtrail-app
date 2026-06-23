import type {
  ListTenantAssertionLedgerExportRowsInput,
  ListTenantAssertionsInput,
} from "@credtrail/db";
import type {
  TenantAssertionLedgerExportQuery,
  TenantAssertionListQuery,
} from "@credtrail/validation";

type TenantAssertionRecordFilterQuery = Pick<
  TenantAssertionLedgerExportQuery,
  "issuedFrom" | "issuedTo" | "badgeTemplateId" | "orgUnitId" | "recipientQuery" | "state"
>;

type TenantAssertionRecordFilterInput = Pick<
  ListTenantAssertionLedgerExportRowsInput,
  "issuedFrom" | "issuedTo" | "badgeTemplateId" | "orgUnitId" | "recipientQuery" | "state"
>;

const applyTenantAssertionRecordFilters = <T extends TenantAssertionRecordFilterInput>(
  input: T,
  query: TenantAssertionRecordFilterQuery,
): T => {
  if (query.issuedFrom !== undefined) {
    input.issuedFrom = query.issuedFrom;
  }

  if (query.issuedTo !== undefined) {
    input.issuedTo = query.issuedTo;
  }

  if (query.badgeTemplateId !== undefined) {
    input.badgeTemplateId = query.badgeTemplateId;
  }

  if (query.orgUnitId !== undefined) {
    input.orgUnitId = query.orgUnitId;
  }

  if (query.recipientQuery !== undefined) {
    input.recipientQuery = query.recipientQuery;
  }

  if (query.state !== undefined) {
    input.state = query.state;
  }

  return input;
};

export const tenantAssertionListDbInput = (
  tenantId: string,
  query: TenantAssertionListQuery,
): ListTenantAssertionsInput => {
  const input: ListTenantAssertionsInput = { tenantId };
  applyTenantAssertionRecordFilters(input, query);

  if (query.limit !== undefined) {
    input.limit = query.limit;
  }

  return input;
};

export const tenantAssertionLedgerExportDbInput = (
  tenantId: string,
  query: TenantAssertionLedgerExportQuery,
): ListTenantAssertionLedgerExportRowsInput => {
  const input: ListTenantAssertionLedgerExportRowsInput = { tenantId };
  return applyTenantAssertionRecordFilters(input, query);
};
