export type TenantOrgUnitValidationReason =
  | "parent_not_permitted"
  | "parent_required"
  | "parent_not_found"
  | "parent_type_not_allowed"
  | "parent_inactive";

export class TenantOrgUnitValidationError extends Error {
  readonly reason: TenantOrgUnitValidationReason;

  constructor(reason: TenantOrgUnitValidationReason, message: string) {
    super(message);
    this.name = "TenantOrgUnitValidationError";
    this.reason = reason;
  }
}

export const isTenantOrgUnitValidationError = (
  error: unknown,
): error is TenantOrgUnitValidationError => {
  return error instanceof TenantOrgUnitValidationError;
};
