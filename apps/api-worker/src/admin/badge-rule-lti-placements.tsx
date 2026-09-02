import type { LtiResourceLinkPlacementRecord } from "@credtrail/db";
import type { HtmlEscapedString } from "hono/utils/html";
import { formatIsoTimestamp } from "../utils/display-format";
import { tenantLtiPlacementRetireAdminPath } from "./access-admin-helpers";
import {
  AdminButton,
  AdminEmptyTableRow,
  AdminListHeader,
  AdminPanel,
  AdminStatusPill,
  AdminTable,
} from "./components";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const PlacementTechnicalDetails = (input: {
  readonly placement: LtiResourceLinkPlacementRecord;
}): HonoElement => {
  return (
    <details class="ct-admin__rule-placement-technical-details">
      <summary>Advanced LMS identifiers</summary>
      <dl>
        <div>
          <dt>Course context ID</dt>
          <dd>{input.placement.contextId ?? "Not recorded"}</dd>
        </div>
        <div>
          <dt>Resource link ID</dt>
          <dd>{input.placement.resourceLinkId}</dd>
        </div>
        <div>
          <dt>Deployment ID</dt>
          <dd>{input.placement.deploymentId}</dd>
        </div>
        <div>
          <dt>Client ID</dt>
          <dd>{input.placement.clientId}</dd>
        </div>
      </dl>
    </details>
  );
};

const PlacementAction = (input: {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly placement: LtiResourceLinkPlacementRecord;
}): HonoElement => {
  if (input.placement.status === "retired") {
    return (
      <p class="ct-admin__rule-placement-retired-copy">
        Retired in CredTrail {formatIsoTimestamp(input.placement.retiredAt)}. A verified launch of
        this LMS link will reactivate it.
      </p>
    );
  }

  return (
    <details class="ct-admin__rule-placement-retire">
      <summary>Retire placement</summary>
      <div>
        <p>
          This removes the placement from active course counts in CredTrail. It does not delete the
          link in the LMS, and that exact link will reactivate if launched again.
        </p>
        <form
          method="post"
          action={tenantLtiPlacementRetireAdminPath(
            input.tenantId,
            input.ruleId,
            input.versionId,
            input.placement.id,
          )}
        >
          <input type="hidden" name="placementId" value={input.placement.id} />
          <AdminButton type="submit" variant="danger" size="tiny">
            Retire placement
          </AdminButton>
        </form>
      </div>
    </details>
  );
};

/** Lists every recorded placement for a rule and offers bounded manual retirement. */
export const BadgeRuleLtiPlacements = (input: {
  readonly tenantId: string;
  readonly ruleId: string;
  readonly versionId: string;
  readonly placements: readonly LtiResourceLinkPlacementRecord[];
}): HonoElement => {
  return (
    <AdminPanel as="section" variant="table" stack={false} className="ct-admin__rule-placements">
      <AdminListHeader
        title="LTI placements"
        description="Recorded LMS links for this rule. Only active placements backed by an active rule appear in course badge counts."
      />
      <AdminTable headers={["Placement", "State", "Last seen", "Action"]} compact>
        {input.placements.length === 0 ? (
          <AdminEmptyTableRow colSpan={4}>
            No LMS placements are recorded for this rule.
          </AdminEmptyTableRow>
        ) : (
          input.placements.map((placement, index) => (
            <tr key={placement.id}>
              <th scope="row">
                <span>Course link {String(index + 1)}</span>
                <PlacementTechnicalDetails placement={placement} />
              </th>
              <td>
                <AdminStatusPill tone={placement.status}>
                  {placement.status === "active" ? "Active" : "Retired"}
                </AdminStatusPill>
              </td>
              <td>{formatIsoTimestamp(placement.lastSeenAt)}</td>
              <td>
                <PlacementAction
                  tenantId={input.tenantId}
                  ruleId={input.ruleId}
                  versionId={input.versionId}
                  placement={placement}
                />
              </td>
            </tr>
          ))
        )}
      </AdminTable>
    </AdminPanel>
  );
};
