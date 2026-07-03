import type { BadgeIssuanceRuleRecord, BadgeIssuanceRuleVersionRecord } from "@credtrail/db";
import type { Child } from "hono/jsx";
import {
  tenantBadgeRuleActivateAdminPath,
  tenantBadgeRuleRecertifyAdminPath,
  tenantBadgeRuleResumeAdminPath,
  tenantBadgeRuleSuspendAdminPath,
  tenantBadgeRuleUpdateLifecycleAdminPath,
} from "../access-admin-helpers";
import { AdminForm } from "../components";
import { CtInput, CtTextarea } from "../../ui/forms";

const lifecycleWindowFields = (input: {
  readonly ruleId: string;
  readonly effectiveStartLabel: string;
  readonly expiryLabel: string;
  readonly submitLabel: string;
}): Child[] => [
  <div class="ct-admin__action-menu-field">
    <label
      class="ct-admin__action-menu-field-label"
      htmlFor={`badge-rule-effective-start-${input.ruleId}`}
    >
      {input.effectiveStartLabel}
    </label>
    <CtInput
      id={`badge-rule-effective-start-${input.ruleId}`}
      name="effectiveStartsAt"
      type="datetime-local"
    />
  </div>,
  <div class="ct-admin__action-menu-field">
    <label
      class="ct-admin__action-menu-field-label"
      htmlFor={`badge-rule-expires-at-${input.ruleId}`}
    >
      {input.expiryLabel}
    </label>
    <CtInput id={`badge-rule-expires-at-${input.ruleId}`} name="expiresAt" type="datetime-local" />
  </div>,
  <button type="submit" class="ct-admin__action-menu-item">
    {input.submitLabel}
  </button>,
];

export const buildBadgeRuleLifecycleMenuActions = (input: {
  readonly tenantId: string;
  readonly rule: BadgeIssuanceRuleRecord;
  readonly latestVersion: BadgeIssuanceRuleVersionRecord;
}): Child[] => {
  const menuActions: Child[] = [];
  const { rule, latestVersion, tenantId } = input;

  if (latestVersion.status === "approved") {
    menuActions.push(
      <AdminForm
        method="post"
        action={tenantBadgeRuleActivateAdminPath(tenantId, rule.id, latestVersion.id)}
        className="ct-admin__action-menu-form ct-admin__action-menu-form--stacked"
      >
        {lifecycleWindowFields({
          ruleId: rule.id,
          effectiveStartLabel: "Effective start",
          expiryLabel: "Expiry",
          submitLabel: "Activate",
        })}
      </AdminForm>,
    );
  }

  if (latestVersion.status === "active") {
    menuActions.push(
      <AdminForm
        method="post"
        action={tenantBadgeRuleUpdateLifecycleAdminPath(tenantId, rule.id, latestVersion.id)}
        className="ct-admin__action-menu-form ct-admin__action-menu-form--stacked"
      >
        {lifecycleWindowFields({
          ruleId: rule.id,
          effectiveStartLabel: "Effective start",
          expiryLabel: "Expiry",
          submitLabel: "Update lifecycle window",
        })}
      </AdminForm>,
      <AdminForm
        method="post"
        action={tenantBadgeRuleSuspendAdminPath(tenantId, rule.id, latestVersion.id)}
        className="ct-admin__action-menu-form ct-admin__action-menu-form--stacked"
      >
        <div class="ct-admin__action-menu-field">
          <label
            class="ct-admin__action-menu-field-label"
            htmlFor={`badge-rule-suspend-reason-${rule.id}`}
          >
            Suspension reason
          </label>
          <CtTextarea
            id={`badge-rule-suspend-reason-${rule.id}`}
            name="reason"
            rows={3}
            required
            placeholder="Explain why issuance is being halted."
          />
        </div>
        <button type="submit" class="ct-admin__action-menu-item ct-admin__action-menu-item--danger">
          Suspend issuance
        </button>
      </AdminForm>,
    );

    if (latestVersion.recertificationDueAt !== null) {
      menuActions.push(
        <AdminForm
          method="post"
          action={tenantBadgeRuleRecertifyAdminPath(tenantId, rule.id, latestVersion.id)}
          className="ct-admin__inline-form"
          dataAttributes={{
            "data-confirm-message": `Record recertification for "${rule.name}"?`,
          }}
        >
          <button type="submit" class="ct-admin__action-menu-item">
            Recertify rule
          </button>
        </AdminForm>,
      );
    }
  }

  if (latestVersion.status === "suspended") {
    menuActions.push(
      <AdminForm
        method="post"
        action={tenantBadgeRuleResumeAdminPath(tenantId, rule.id, latestVersion.id)}
        className="ct-admin__inline-form"
        dataAttributes={{
          "data-confirm-message": `Resume issuance for "${rule.name}"?`,
        }}
      >
        <button type="submit" class="ct-admin__action-menu-item">
          Resume issuance
        </button>
      </AdminForm>,
    );
  }

  return menuActions;
};
