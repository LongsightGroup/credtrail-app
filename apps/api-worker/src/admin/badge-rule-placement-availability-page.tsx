import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeRulePlacementAvailabilityRecord,
  TenantLmsCourseContextRecord,
  TenantMembershipRole,
  TenantOrgUnitRecord,
  TenantRecord,
} from "@credtrail/db";
import type { GradebookCourseRecord } from "../lms/gradebook-types";
import type { AppPage } from "../ui/render-page";
import { CtInput, CtSelect } from "../ui/forms";
import {
  buildBadgeRulePlacementAvailabilityPath,
  buildRulesAdminPath,
  tenantBadgeRulePlacementAvailabilityCourseAddPath,
  tenantBadgeRulePlacementAvailabilityCourseMapPath,
  tenantBadgeRulePlacementAvailabilityCourseRemovePath,
  tenantBadgeRulePlacementAvailabilityRemovePath,
  tenantBadgeRulePlacementAvailabilityUpdatePath,
} from "./access-admin-helpers";
import {
  AdminActions,
  AdminButton,
  AdminField,
  AdminForm,
  AdminPanel,
  AdminStatus,
  AdminStatusPill,
} from "./components";
import { renderInstitutionAdminShellPage } from "./institution-admin-shell";

interface AvailabilityConnectionOption {
  readonly id: string;
  readonly displayName: string;
}

interface SelectedCourseView {
  readonly context: TenantLmsCourseContextRecord;
  readonly connectionName: string;
}

interface AvailabilityCourseSearchView {
  readonly connectionId: string;
  readonly connectionName: string;
  readonly query: string;
  readonly courses: readonly GradebookCourseRecord[];
  readonly hasMore: boolean;
  readonly error: string | null;
}

export interface BadgeRulePlacementAvailabilityPageInput {
  readonly tenant: TenantRecord;
  readonly userId: string;
  readonly userEmail?: string | undefined;
  readonly membershipRole: TenantMembershipRole;
  readonly switchOrganizationPath?: string | null | undefined;
  readonly rule: BadgeIssuanceRuleRecord;
  readonly activeVersion: BadgeIssuanceRuleVersionRecord | null;
  readonly activeReferenceInvalid: boolean;
  readonly availability: BadgeRulePlacementAvailabilityRecord | null;
  readonly selectedCourses: readonly SelectedCourseView[];
  readonly activeScopeRoots: readonly TenantOrgUnitRecord[];
  readonly activeMappingParents: readonly TenantOrgUnitRecord[];
  readonly connections: readonly AvailabilityConnectionOption[];
  readonly defaultConnectionId: string | null;
  readonly orgCoverageCount: number;
  readonly mappedCourseCount: number;
  readonly unmappedCourseCount: number;
  readonly catalogedCourseCount: number;
  readonly search: AvailabilityCourseSearchView | null;
  readonly flash: { readonly tone: "success" | "error"; readonly message: string } | null;
}

const pluralize = (count: number, singular: string, plural = `${singular}s`): string => {
  return `${String(count)} ${count === 1 ? singular : plural}`;
};

const availabilitySummary = (input: BadgeRulePlacementAvailabilityPageInput): string => {
  const availability = input.availability;

  if (availability === null) {
    return "Not offered";
  }

  switch (availability.scope) {
    case "selected_courses":
      return pluralize(input.selectedCourses.length, "selected course");
    case "tenant":
      return "Every course in this institution";
    case "org_unit_subtree": {
      const root = input.activeScopeRoots.find(
        (candidate) => candidate.id === availability.rootOrgUnitId,
      );
      return root === undefined
        ? "Organizational area unavailable"
        : `Organizational area: ${root.displayName}`;
    }
  }
};

const selectedScopeFields = (input: BadgeRulePlacementAvailabilityPageInput) => {
  return (
    <div class="ct-rule-availability__scope-detail" data-scope-detail="selected_courses">
      <h3>Selected courses</h3>
      {input.selectedCourses.length === 0 ? (
        <AdminStatus tone="info">
          Search for a course below and add it before publishing this scope.
        </AdminStatus>
      ) : (
        <>
          <p>
            This rule will be offered only in the{" "}
            {pluralize(input.selectedCourses.length, "course")} listed below.
          </p>
          {input.selectedCourses.map(({ context }) => (
            <CtInput type="hidden" name="courseContextIds" value={context.id} />
          ))}
        </>
      )}
    </div>
  );
};

const orgScopeFields = (input: BadgeRulePlacementAvailabilityPageInput) => {
  const selectedRootId =
    input.availability?.scope === "org_unit_subtree"
      ? input.availability.rootOrgUnitId
      : input.activeScopeRoots[0]?.id;

  return (
    <div class="ct-rule-availability__scope-detail" data-scope-detail="org_unit_subtree">
      <AdminField label="Organizational area">
        <CtSelect name="rootOrgUnitId" required={input.activeScopeRoots.length > 0}>
          {input.activeScopeRoots.length === 0 ? (
            <option value="" selected>
              No active organizational areas
            </option>
          ) : (
            input.activeScopeRoots.map((unit) => (
              <option value={unit.id} selected={unit.id === selectedRootId}>
                {unit.displayName}
              </option>
            ))
          )}
        </CtSelect>
      </AdminField>
      <div class="ct-rule-availability__impact" aria-live="polite">
        <strong>Review the reach</strong>
        <p>
          The current selection includes {pluralize(input.orgCoverageCount, "mapped course")}.
          {input.unmappedCourseCount > 0
            ? ` ${pluralize(input.unmappedCourseCount, "cataloged course")} remain excluded because they are not mapped to an organizational area.`
            : " All cataloged courses with organizational mappings are accounted for."}
        </p>
        {input.orgCoverageCount === 0 ? (
          <AdminStatus tone="warning">
            No mapped courses currently fall within this area. The rule will not appear until a
            course is mapped there.
          </AdminStatus>
        ) : null}
        <label class="ct-rule-availability__confirmation" for="confirm-org-impact">
          <input
            id="confirm-org-impact"
            name="confirmImpact"
            type="checkbox"
            value="confirmed"
            class="ct-checkbox-field__control"
          />
          <span>I have reviewed which mapped courses will receive this rule.</span>
        </label>
      </div>
    </div>
  );
};

const tenantScopeFields = (input: BadgeRulePlacementAvailabilityPageInput) => {
  return (
    <div class="ct-rule-availability__scope-detail" data-scope-detail="tenant">
      <div class="ct-rule-availability__impact">
        <strong>Review the reach</strong>
        <p>
          CredTrail has cataloged {pluralize(input.catalogedCourseCount, "course")} across this
          institution's connected LMS accounts. New courses discovered later will also receive this
          rule.
        </p>
        <label class="ct-rule-availability__confirmation" for="confirm-tenant-impact">
          <input
            id="confirm-tenant-impact"
            name="confirmImpact"
            type="checkbox"
            value="confirmed"
            class="ct-checkbox-field__control"
          />
          <span>I have reviewed the institution-wide impact.</span>
        </label>
      </div>
    </div>
  );
};

const scopeForm = (input: BadgeRulePlacementAvailabilityPageInput) => {
  const currentScope = input.availability?.scope ?? "selected_courses";
  const isActive = input.activeVersion !== null && !input.activeReferenceInvalid;

  return (
    <AdminPanel as="section" className="ct-rule-availability__scope-panel">
      <div>
        <h2>Choose where faculty can add this rule</h2>
        <p>Changing availability does not change the rule requirements or who earns the badge.</p>
      </div>
      <AdminForm
        method="post"
        action={tenantBadgeRulePlacementAvailabilityUpdatePath(input.tenant.id, input.rule.id)}
        className="ct-admin__form ct-stack ct-rule-availability__scope-form"
      >
        <fieldset class="ct-rule-availability__scope-choices">
          <legend>Course availability</legend>
          <label for="availability-scope-selected" aria-label="Selected courses">
            <input
              id="availability-scope-selected"
              name="scope"
              type="radio"
              value="selected_courses"
              class="ct-checkbox-field__control"
              checked={currentScope === "selected_courses"}
            />
            <span>
              <strong>Selected courses</strong>
              <small>Offer this rule only in courses you add below.</small>
            </span>
          </label>
          <label for="availability-scope-org" aria-label="An organizational area">
            <input
              id="availability-scope-org"
              name="scope"
              type="radio"
              value="org_unit_subtree"
              class="ct-checkbox-field__control"
              checked={currentScope === "org_unit_subtree"}
            />
            <span>
              <strong>An organizational area</strong>
              <small>
                Offer this rule in mapped courses within one college, department, or program.
              </small>
            </span>
          </label>
          <label for="availability-scope-tenant" aria-label="Every course in this institution">
            <input
              id="availability-scope-tenant"
              name="scope"
              type="radio"
              value="tenant"
              class="ct-checkbox-field__control"
              checked={currentScope === "tenant"}
            />
            <span>
              <strong>Every course in this institution</strong>
              <small>Offer this rule wherever its LMS connection is available.</small>
            </span>
          </label>
        </fieldset>
        {selectedScopeFields(input)}
        {orgScopeFields(input)}
        {tenantScopeFields(input)}
        <AdminButton type="submit" variant="primary" disabled={!isActive}>
          Update course availability
        </AdminButton>
        {!isActive ? (
          <AdminStatus tone="warning">
            Activate a valid rule version before setting course availability.
          </AdminStatus>
        ) : null}
      </AdminForm>
    </AdminPanel>
  );
};

const selectedCourseList = (input: BadgeRulePlacementAvailabilityPageInput) => {
  return (
    <AdminPanel as="section" className="ct-rule-availability__courses">
      <div>
        <h2>Selected courses</h2>
        <p>These courses are saved for the selected-courses scope.</p>
      </div>
      {input.selectedCourses.length === 0 ? (
        <AdminStatus tone="info">No courses have been selected.</AdminStatus>
      ) : (
        <ul class="ct-rule-availability__course-list">
          {input.selectedCourses.map(({ context, connectionName }) => (
            <li>
              <div>
                <strong>{context.displayName}</strong>
                <small>
                  {context.courseCode === null
                    ? connectionName
                    : `${context.courseCode} · ${connectionName}`}
                </small>
              </div>
              <AdminForm
                method="post"
                action={tenantBadgeRulePlacementAvailabilityCourseRemovePath(
                  input.tenant.id,
                  input.rule.id,
                )}
                className="ct-admin__action-menu-form"
              >
                <CtInput type="hidden" name="courseContextId" value={context.id} />
                <AdminButton
                  type="submit"
                  variant="quiet"
                  size="tiny"
                  ariaLabel={`Remove ${context.displayName} from selected courses`}
                >
                  Remove
                </AdminButton>
              </AdminForm>
            </li>
          ))}
        </ul>
      )}
    </AdminPanel>
  );
};

const courseSearchResults = (input: BadgeRulePlacementAvailabilityPageInput) => {
  const search = input.search;

  if (search === null) {
    return null;
  }

  if (search.error !== null) {
    return <AdminStatus tone="error">{search.error}</AdminStatus>;
  }

  if (search.courses.length === 0) {
    return <AdminStatus tone="info">No courses matched this search.</AdminStatus>;
  }

  return (
    <div class="ct-rule-availability__search-results">
      <h3>Search results</h3>
      <p aria-live="polite">
        Found {pluralize(search.courses.length, "course")} in {search.connectionName}.
        {search.hasMore ? " Refine the search to see a shorter list." : ""}
      </p>
      <ul class="ct-rule-availability__course-list">
        {search.courses.map((course) => (
          <li>
            <div>
              <strong>{course.title}</strong>
              {course.courseCode === null ? null : <small>{course.courseCode}</small>}
            </div>
            <div class="ct-rule-availability__course-actions">
              <AdminForm
                method="post"
                action={tenantBadgeRulePlacementAvailabilityCourseAddPath(
                  input.tenant.id,
                  input.rule.id,
                )}
                className="ct-admin__action-menu-form"
              >
                <CtInput type="hidden" name="connectionId" value={search.connectionId} />
                <CtInput type="hidden" name="courseId" value={course.courseId} />
                <AdminButton
                  type="submit"
                  variant="secondary"
                  size="tiny"
                  ariaLabel={`Add ${course.title} to selected courses`}
                >
                  Add course
                </AdminButton>
              </AdminForm>
              {input.activeMappingParents.length === 0 ? null : (
                <AdminForm
                  method="post"
                  action={tenantBadgeRulePlacementAvailabilityCourseMapPath(
                    input.tenant.id,
                    input.rule.id,
                  )}
                  className="ct-rule-availability__mapping-form"
                >
                  <CtInput type="hidden" name="connectionId" value={search.connectionId} />
                  <CtInput type="hidden" name="courseId" value={course.courseId} />
                  <label for={`mapping-parent-${course.courseId}`}>
                    <span>Department or program</span>
                    <CtSelect
                      id={`mapping-parent-${course.courseId}`}
                      name="parentOrgUnitId"
                      required
                    >
                      {input.activeMappingParents.map((unit) => (
                        <option value={unit.id}>{unit.displayName}</option>
                      ))}
                    </CtSelect>
                  </label>
                  <AdminButton
                    type="submit"
                    variant="quiet"
                    size="tiny"
                    ariaLabel={`Map ${course.title} to an organizational area`}
                  >
                    Map LMS course
                  </AdminButton>
                </AdminForm>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
};

const courseSearch = (input: BadgeRulePlacementAvailabilityPageInput) => {
  const pagePath = buildBadgeRulePlacementAvailabilityPath(input.tenant.id, input.rule.id);
  const connectionId = input.search?.connectionId ?? input.defaultConnectionId ?? undefined;

  return (
    <AdminPanel as="section" className="ct-rule-availability__course-search">
      <div>
        <h2>Find an LMS course</h2>
        <p>Add a course to the selected list or map it to a department or program.</p>
      </div>
      {input.connections.length === 0 ? (
        <AdminStatus tone="warning">Connect an LMS before searching for courses.</AdminStatus>
      ) : (
        <search>
          <AdminForm
            method="get"
            action={pagePath}
            className="ct-admin__form ct-rule-availability__search-form"
          >
            <AdminField label="LMS connection">
              <CtSelect name="connectionId" required>
                {input.connections.map((connection) => (
                  <option value={connection.id} selected={connection.id === connectionId}>
                    {connection.displayName}
                  </option>
                ))}
              </CtSelect>
            </AdminField>
            <AdminField label="Course name or code">
              <CtInput
                type="search"
                name="q"
                value={input.search?.query ?? ""}
                maxlength={120}
                required
              />
            </AdminField>
            <AdminButton type="submit" variant="secondary">
              Search courses
            </AdminButton>
          </AdminForm>
        </search>
      )}
      {courseSearchResults(input)}
      {input.activeMappingParents.length === 0 && input.connections.length > 0 ? (
        <AdminStatus tone="warning">
          Add an active department or program before mapping LMS courses to organizational areas.
        </AdminStatus>
      ) : null}
      <p class="ct-rule-availability__mapping-summary">
        {pluralize(input.mappedCourseCount, "cataloged course")} mapped;{" "}
        {pluralize(input.unmappedCourseCount, "course")} not mapped.
      </p>
    </AdminPanel>
  );
};

const stopOffering = (input: BadgeRulePlacementAvailabilityPageInput) => {
  if (input.availability === null) {
    return null;
  }

  return (
    <AdminPanel as="section" className="ct-rule-availability__stop-panel">
      <div>
        <h2>Stop offering this rule</h2>
        <p>
          This removes the current availability policy. Course mappings and placement history remain
          intact.
        </p>
      </div>
      <AdminForm
        method="post"
        action={tenantBadgeRulePlacementAvailabilityRemovePath(input.tenant.id, input.rule.id)}
      >
        <label class="ct-rule-availability__confirmation" for="confirm-stop-offering">
          <input
            id="confirm-stop-offering"
            name="confirmRemoval"
            type="checkbox"
            value="confirmed"
            class="ct-checkbox-field__control"
            required
          />
          <span>I understand faculty will no longer be able to add this rule to courses.</span>
        </label>
        <AdminActions>
          <AdminButton type="submit" variant="danger">
            Stop offering in courses
          </AdminButton>
        </AdminActions>
      </AdminForm>
    </AdminPanel>
  );
};

/** Builds the rule-owned administrator workflow for placement availability. */
export const badgeRulePlacementAvailabilityPage = (
  input: BadgeRulePlacementAvailabilityPageInput,
): AppPage => {
  return renderInstitutionAdminShellPage({
    tenant: input.tenant,
    userId: input.userId,
    ...(input.userEmail === undefined ? {} : { userEmail: input.userEmail }),
    membershipRole: input.membershipRole,
    view: "rules",
    title: `${input.rule.name} · Course availability · Institution Admin · ${input.tenant.displayName}`,
    assets: [
      "institutionAdminCss",
      "institutionAdminRuleAvailabilityCss",
      "institutionAdminShellJs",
    ],
    contextJson: {},
    ...(input.switchOrganizationPath === undefined
      ? {}
      : { switchOrganizationPath: input.switchOrganizationPath }),
    children: (
      <>
        <header class="ct-admin-page-header ct-rule-availability__header">
          <p>
            <a href={buildRulesAdminPath(input.tenant.id)}>← All rules</a>
          </p>
          <h1>{input.rule.name}</h1>
          <p>
            Course availability controls where faculty can add this rule. Eligibility still comes
            from the rule's requirements.
          </p>
        </header>
        <section class="ct-admin ct-stack ct-rule-availability">
          {input.flash === null ? null : (
            <AdminStatus tone={input.flash.tone}>{input.flash.message}</AdminStatus>
          )}
          <AdminPanel as="section" className="ct-rule-availability__summary">
            <div>
              <h2>Current availability</h2>
              <p class="ct-rule-availability__current">{availabilitySummary(input)}</p>
            </div>
            {input.activeReferenceInvalid ? (
              <AdminStatus tone="error">
                The rule's saved active version could not be found. Repair the rule before changing
                availability.
              </AdminStatus>
            ) : input.activeVersion === null ? (
              <AdminStatus tone="warning">
                This rule has no active version, so it cannot be offered in courses.
              </AdminStatus>
            ) : (
              <AdminStatusPill tone="active">
                Active version {String(input.activeVersion.versionNumber)}
              </AdminStatusPill>
            )}
          </AdminPanel>
          {scopeForm(input)}
          {selectedCourseList(input)}
          {courseSearch(input)}
          {stopOffering(input)}
        </section>
      </>
    ),
  });
};
