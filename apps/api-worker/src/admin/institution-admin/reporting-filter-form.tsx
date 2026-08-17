import type { TenantReportingLifecycleFilter } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { AdminActions, AdminButton, AdminButtonLink, AdminField, AdminForm } from "../components";
import { CtInput, CtSelect } from "../../ui/forms";
import type { InstitutionAdminPageInput } from "./page-types";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

/** Normalized reporting filter values used by page renderers and export links. */
export interface InstitutionAdminReportingFilterValues {
  readonly issuedFrom: string;
  readonly issuedTo: string;
  readonly badgeTemplateId: string;
  readonly orgUnitId: string;
  readonly state: TenantReportingLifecycleFilter | null;
}

/** Resolves the current reporting filters without requiring an overview query result. */
export const reportingFilterValuesFromPage = (
  page: InstitutionAdminPageInput,
): InstitutionAdminReportingFilterValues => {
  const filters = page.reportingFilters ?? page.reportingOverview?.filters;

  return {
    issuedFrom: filters?.issuedFrom ?? "",
    issuedTo: filters?.issuedTo ?? "",
    badgeTemplateId: filters?.badgeTemplateId ?? "",
    orgUnitId: filters?.orgUnitId ?? "",
    state: filters?.state ?? null,
  };
};

/** Renders the shared idempotent reporting filter form. */
export const renderInstitutionAdminReportingFiltersForm = (input: {
  readonly page: InstitutionAdminPageInput;
  readonly actionPath: string;
  readonly formClass?: string;
  readonly resetPath?: string;
}): HonoElement => {
  const filters = reportingFilterValuesFromPage(input.page);
  const formClass = input.formClass ?? "ct-admin__form ct-admin__form--inline ct-grid";
  const resetPath = input.resetPath ?? input.actionPath;

  return (
    <>
      <AdminForm
        id="reporting-filters-form"
        method="get"
        action={input.actionPath}
        className={formClass}
        dataAttributes={{
          "data-reporting-submit-state": "idle",
        }}
      >
        <AdminField label="Issued from">
          <CtInput name="issuedFrom" type="date" value={filters.issuedFrom} />
        </AdminField>
        <AdminField label="Issued to">
          <CtInput name="issuedTo" type="date" value={filters.issuedTo} />
        </AdminField>
        <AdminField label="Badge template">
          <CtSelect name="badgeTemplateId">
            <option value="">All templates</option>
            {input.page.badgeTemplates.map((template) => (
              <option value={template.id} selected={filters.badgeTemplateId === template.id}>
                {template.title}
              </option>
            ))}
          </CtSelect>
        </AdminField>
        <AdminField label="Org unit">
          <CtSelect name="orgUnitId">
            <option value="">All org units</option>
            {input.page.orgUnits
              .filter((orgUnit) => orgUnit.isActive)
              .map((orgUnit) => (
                <option value={orgUnit.id} selected={filters.orgUnitId === orgUnit.id}>
                  {`${orgUnit.displayName} (${orgUnit.unitType})`}
                </option>
              ))}
          </CtSelect>
        </AdminField>
        <AdminField label="Lifecycle state">
          <CtSelect name="state">
            <option value="">All current states</option>
            <option value="active" selected={filters.state === "active"}>
              active
            </option>
            <option value="suspended" selected={filters.state === "suspended"}>
              suspended
            </option>
            <option value="revoked" selected={filters.state === "revoked"}>
              revoked
            </option>
            <option value="expired" selected={filters.state === "expired"}>
              expired
            </option>
            <option value="pending_review" selected={filters.state === "pending_review"}>
              pending review
            </option>
          </CtSelect>
        </AdminField>
        <AdminActions>
          <AdminButton type="submit">Apply filters</AdminButton>
          <AdminButtonLink href={resetPath} variant="secondary">
            Reset
          </AdminButtonLink>
        </AdminActions>
      </AdminForm>
      <p
        id="reporting-filters-status"
        class="ct-admin__hint"
        data-reporting-submit-status
        aria-live="polite"
      >
        Applying filters refreshes this page with your current selection.
      </p>
    </>
  );
};
