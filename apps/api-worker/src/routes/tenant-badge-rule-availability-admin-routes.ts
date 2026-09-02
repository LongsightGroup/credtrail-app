import {
  assignLmsCourseContextOrgUnit,
  createAuditLog,
  ensureExternalCourseOrgUnit,
  findBadgeRulePlacementAvailability,
  findTenantOrgUnitById,
  listTenantLmsConnections,
  listTenantLmsCourseContexts,
  listTenantOrgUnits,
  removeBadgeRulePlacementAvailability,
  replaceBadgeRulePlacementAvailability,
  resolveBadgeIssuanceRuleVersionSelection,
  upsertCatalogLmsCourseContext,
  type BadgeRulePlacementAvailabilityRecord,
  type TenantLmsCourseContextRecord,
  type TenantMembershipRole,
  type TenantOrgUnitRecord,
} from "@credtrail/db";
import {
  parseAddBadgeRulePlacementAvailabilityCourseAdminRequest,
  parseBadgeRulePlacementAvailabilityPathParams,
  parseBadgeRulePlacementAvailabilitySearchQuery,
  parseMapBadgeRulePlacementAvailabilityCourseAdminRequest,
  parseRemoveBadgeRulePlacementAvailabilityAdminRequest,
  parseRemoveBadgeRulePlacementAvailabilityCourseAdminRequest,
  parseUpdateBadgeRulePlacementAvailabilityAdminRequest,
  type ReplaceBadgeRulePlacementAvailabilityRequest,
} from "@credtrail/validation";
import type { Hono } from "hono";
import {
  badgeRulePlacementAvailabilityPage,
  type BadgeRulePlacementAvailabilityPageInput,
} from "../admin/badge-rule-placement-availability-page";
import { buildBadgeRulePlacementAvailabilityPath } from "../admin/access-admin-helpers";
import { readOptionalFormField } from "../admin/admin-form-helpers";
import { consumeAdminListMessageFlash } from "../admin/admin-list-message-flash";
import { redirectWithAdminListFlash } from "../admin/admin-list-flash-redirect";
import type { AppContext, AppEnv } from "../app/types";
import type { ResolveDatabase } from "../app/route-deps";
import type { AuthenticatedPrincipal } from "../auth/auth-context";
import type {
  LmsCourseAuthoringFailure,
  LmsCourseAuthoringService,
} from "../lms/lms-course-authoring-service";
import type { GradebookCourseRecord } from "../lms/gradebook-types";
import { renderAppPage } from "../ui/render-page";
import {
  loadBadgeRuleVersionsPageContext,
  type BadgeRuleVersionsPageContext,
} from "./badge-rule-version-page-context";
import type { TenantGovernanceAdminPageDataLoaders } from "./tenant-governance-admin/page-data";

interface RegisterTenantBadgeRuleAvailabilityAdminRoutesInput {
  readonly app: Hono<AppEnv>;
  readonly resolveDatabase: ResolveDatabase;
  readonly lmsCourseAuthoring: LmsCourseAuthoringService;
  readonly loadInstitutionAdminShellData: TenantGovernanceAdminPageDataLoaders["loadInstitutionAdminShellData"];
  readonly resolveInstitutionAdminAdminRole: (
    c: AppContext,
    tenantId: string,
    nextPath: string,
  ) => Promise<
    | Response
    | {
        readonly principal: AuthenticatedPrincipal;
        readonly membershipRole: TenantMembershipRole;
      }
  >;
}

interface AuthorizedAvailabilityContext extends BadgeRuleVersionsPageContext {
  readonly path: string;
}

const SEARCH_RESULT_LIMIT = 25;
const AVAILABILITY_WORKSPACE = "rule_availability" as const;

const redirectToAvailability = (
  c: AppContext,
  input: {
    readonly tenantId: string;
    readonly ruleId: string;
    readonly userId: string;
    readonly tone: "success" | "error";
    readonly message: string;
  },
): Promise<Response> => {
  return redirectWithAdminListFlash(c, {
    tenantId: input.tenantId,
    userId: input.userId,
    workspace: AVAILABILITY_WORKSPACE,
    path: buildBadgeRulePlacementAvailabilityPath(input.tenantId, input.ruleId),
    tone: input.tone,
    message: input.message,
  });
};

const loadAuthorizedAvailabilityContext = async (
  c: AppContext,
  input: Pick<
    RegisterTenantBadgeRuleAvailabilityAdminRoutesInput,
    "resolveDatabase" | "resolveInstitutionAdminAdminRole"
  > & {
    readonly tenantId: string;
    readonly ruleId: string;
  },
): Promise<Response | AuthorizedAvailabilityContext> => {
  const path = buildBadgeRulePlacementAvailabilityPath(input.tenantId, input.ruleId);
  const loaded = await loadBadgeRuleVersionsPageContext(c, {
    tenantId: input.tenantId,
    ruleId: input.ruleId,
    nextPath: path,
    resolveDatabase: input.resolveDatabase,
    resolveActor: input.resolveInstitutionAdminAdminRole,
  });

  return loaded instanceof Response ? loaded : { ...loaded, path };
};

const formStrings = (formData: FormData, name: string): readonly string[] => {
  return formData
    .getAll(name)
    .filter((value): value is string => typeof value === "string")
    .map((value) => value.trim());
};

const connectionAllowedForRule = (
  context: BadgeRuleVersionsPageContext,
  connectionId: string,
): boolean => {
  return context.rule.lmsConnectionId === null
    ? false
    : context.rule.lmsConnectionId === connectionId;
};

const resolveExactCourse = async (
  c: AppContext,
  input: {
    readonly service: LmsCourseAuthoringService;
    readonly context: AuthorizedAvailabilityContext;
    readonly connectionId: string;
    readonly courseId: string;
  },
): Promise<GradebookCourseRecord | LmsCourseAuthoringFailure | null> => {
  if (!connectionAllowedForRule(input.context, input.connectionId)) {
    return null;
  }

  const result = await input.service.resolveCourses(
    {
      db: input.context.db,
      tenantId: input.context.rule.tenantId,
      connectionId: input.connectionId,
      userId: input.context.principal.userId,
      courseIds: [input.courseId],
    },
    { signal: c.req.raw.signal },
  );

  if (result.status !== "resolved") {
    return result;
  }

  return result.courses.length === 1 && result.courses[0]?.courseId === input.courseId
    ? result.courses[0]
    : null;
};

const courseResolutionError = (result: LmsCourseAuthoringFailure | null): string => {
  if (result === null) {
    return "That course is no longer available for this rule. Search again and choose a current result.";
  }

  switch (result.status) {
    case "identity_unlinked":
      return "Connect your LMS identity before choosing a course.";
    case "course_unauthorized":
      return "You no longer have access to that LMS course. Choose another course or ask an LMS administrator for access.";
    case "connection_not_found":
      return "The rule's LMS connection could not be found. Check the connection and try again.";
    case "connection_unusable":
      return "The rule's LMS connection needs attention before courses can be selected.";
    case "provider_unavailable":
    case "dependency_unavailable":
    case "request_cancelled":
      return "The LMS course could not be verified right now. Try again after the connection is available.";
  }
};

const replaceAvailabilityError = (
  status: Exclude<
    Awaited<ReturnType<typeof replaceBadgeRulePlacementAvailability>>["status"],
    "updated" | "unchanged"
  >,
): string => {
  switch (status) {
    case "not_authorized":
      return "Only institution owners and administrators can change course availability.";
    case "rule_not_found":
      return "This badge rule could not be found.";
    case "rule_not_active":
      return "Activate the rule before setting course availability.";
    case "course_context_not_found":
      return "One of the selected courses is no longer available. Refresh the page and try again.";
    case "org_unit_not_found":
      return "That organizational area could not be found. Choose another area.";
    case "org_unit_inactive":
      return "That organizational area is inactive. Choose an active area.";
    case "org_unit_not_course":
      return "The saved course mapping is invalid. Map the course again before continuing.";
  }
};

const replaceAvailability = async (
  context: AuthorizedAvailabilityContext,
  availability: ReplaceBadgeRulePlacementAvailabilityRequest,
): Promise<{ readonly tone: "success" | "error"; readonly message: string }> => {
  const result = await replaceBadgeRulePlacementAvailability(context.db, {
    tenantId: context.rule.tenantId,
    ruleId: context.rule.id,
    availability,
    actorUserId: context.principal.userId,
    actorRole: context.membershipRole,
  });

  return result.status === "updated"
    ? { tone: "success", message: "Course availability updated." }
    : result.status === "unchanged"
      ? { tone: "success", message: "Course availability is already up to date." }
      : { tone: "error", message: replaceAvailabilityError(result.status) };
};

const isCourseWithinRoot = (
  courseContext: TenantLmsCourseContextRecord,
  rootOrgUnitId: string,
  orgUnitsById: ReadonlyMap<string, TenantOrgUnitRecord>,
): boolean => {
  let currentId = courseContext.courseOrgUnitId;
  const visited = new Set<string>();

  while (currentId !== null && !visited.has(currentId)) {
    if (currentId === rootOrgUnitId) {
      return true;
    }

    visited.add(currentId);
    currentId = orgUnitsById.get(currentId)?.parentOrgUnitId ?? null;
  }

  return false;
};

const countCoursesWithinRoot = (
  contexts: readonly TenantLmsCourseContextRecord[],
  rootOrgUnitId: string,
  orgUnits: readonly TenantOrgUnitRecord[],
): number => {
  const orgUnitsById = new Map(orgUnits.map((unit) => [unit.id, unit]));
  return contexts.filter((context) => isCourseWithinRoot(context, rootOrgUnitId, orgUnitsById))
    .length;
};

const searchableConnections = (
  context: AuthorizedAvailabilityContext,
  connections: Awaited<ReturnType<typeof listTenantLmsConnections>>,
) => {
  return connections.filter(
    (connection) =>
      connection.id === context.rule.lmsConnectionId &&
      connection.providerKind === context.rule.lmsProviderKind,
  );
};

const loadSearch = async (
  c: AppContext,
  input: {
    readonly context: AuthorizedAvailabilityContext;
    readonly service: LmsCourseAuthoringService;
    readonly connectionId: string | undefined;
    readonly query: string | undefined;
    readonly connectionName: string | undefined;
  },
): Promise<BadgeRulePlacementAvailabilityPageInput["search"]> => {
  if (input.connectionId === undefined || input.query === undefined) {
    return null;
  }

  if (
    input.connectionName === undefined ||
    !connectionAllowedForRule(input.context, input.connectionId)
  ) {
    return {
      connectionId: input.connectionId,
      connectionName: "Selected LMS connection",
      query: input.query,
      courses: [],
      hasMore: false,
      error: "Choose the LMS connection assigned to this rule.",
    };
  }

  const result = await input.service.searchCourses(
    {
      db: input.context.db,
      tenantId: input.context.rule.tenantId,
      connectionId: input.connectionId,
      userId: input.context.principal.userId,
      searchTerm: input.query,
      limit: SEARCH_RESULT_LIMIT,
    },
    { signal: c.req.raw.signal },
  );

  return result.status === "resolved"
    ? {
        connectionId: input.connectionId,
        connectionName: input.connectionName,
        query: input.query,
        courses: result.courses,
        hasMore: result.hasMore,
        error: null,
      }
    : {
        connectionId: input.connectionId,
        connectionName: input.connectionName,
        query: input.query,
        courses: [],
        hasMore: false,
        error: courseResolutionError(result),
      };
};

const renderAvailabilityPage = async (
  c: AppContext,
  input: {
    readonly routes: RegisterTenantBadgeRuleAvailabilityAdminRoutesInput;
    readonly context: AuthorizedAvailabilityContext;
    readonly searchConnectionId: string | undefined;
    readonly searchQuery: string | undefined;
  },
): Promise<Response> => {
  const { context } = input;
  const [shell, availability, orgUnits, allConnections, courseContexts, flash] = await Promise.all([
    input.routes.loadInstitutionAdminShellData(
      c,
      context.rule.tenantId,
      context.principal.userId,
      context.membershipRole,
    ),
    findBadgeRulePlacementAvailability(context.db, {
      tenantId: context.rule.tenantId,
      ruleId: context.rule.id,
    }),
    listTenantOrgUnits(context.db, { tenantId: context.rule.tenantId }),
    listTenantLmsConnections(context.db, context.rule.tenantId),
    listTenantLmsCourseContexts(context.db, { tenantId: context.rule.tenantId }),
    consumeAdminListMessageFlash(c, {
      tenantId: context.rule.tenantId,
      userId: context.principal.userId,
      workspace: AVAILABILITY_WORKSPACE,
    }),
  ]);

  if (shell instanceof Response) {
    return shell;
  }

  const connections = searchableConnections(context, allConnections);
  const connectionNames = new Map(
    connections.map((connection) => [connection.id, connection.displayName]),
  );
  const selectedIds = new Set(
    availability?.scope === "selected_courses" ? availability.courseContextIds : [],
  );
  const selectedCourses = courseContexts
    .filter((courseContext) => selectedIds.has(courseContext.id))
    .map((courseContext) => ({
      context: courseContext,
      connectionName: connectionNames.get(courseContext.lmsConnectionId) ?? "LMS course",
    }));
  const activeScopeRoots = orgUnits.filter((unit) => unit.unitType !== "course");
  const activeMappingParents = orgUnits.filter(
    (unit) => unit.unitType === "department" || unit.unitType === "program",
  );
  const mappedCourseCount = courseContexts.filter(
    (courseContext) => courseContext.courseOrgUnitId !== null,
  ).length;
  const rootId =
    availability?.scope === "org_unit_subtree"
      ? availability.rootOrgUnitId
      : activeScopeRoots[0]?.id;
  const search = await loadSearch(c, {
    context,
    service: input.routes.lmsCourseAuthoring,
    connectionId: input.searchConnectionId,
    query: input.searchQuery,
    connectionName:
      input.searchConnectionId === undefined
        ? undefined
        : connectionNames.get(input.searchConnectionId),
  });
  const selection = resolveBadgeIssuanceRuleVersionSelection({
    rule: context.rule,
    versions: context.versions,
  });

  return renderAppPage(
    c,
    badgeRulePlacementAvailabilityPage({
      tenant: shell.tenant,
      userId: shell.userId,
      ...(shell.userEmail === undefined ? {} : { userEmail: shell.userEmail }),
      membershipRole: shell.membershipRole,
      switchOrganizationPath: shell.switchOrganizationPath,
      rule: context.rule,
      activeVersion: selection._tag === "resolved" ? selection.activeVersion : null,
      activeReferenceInvalid: selection._tag === "invalid_active_reference",
      availability,
      selectedCourses,
      activeScopeRoots,
      activeMappingParents,
      connections: connections.map((connection) => ({
        id: connection.id,
        displayName: connection.displayName,
      })),
      defaultConnectionId: context.rule.lmsConnectionId,
      orgCoverageCount:
        rootId === undefined ? 0 : countCoursesWithinRoot(courseContexts, rootId, orgUnits),
      mappedCourseCount,
      unmappedCourseCount: courseContexts.length - mappedCourseCount,
      catalogedCourseCount: courseContexts.length,
      search,
      flash,
    }),
  );
};

const mapScopeFormRequest = (formData: FormData): unknown => {
  const scope = readOptionalFormField(formData, "scope");

  switch (scope) {
    case "selected_courses":
      return { scope, courseContextIds: formStrings(formData, "courseContextIds") };
    case "org_unit_subtree":
      return {
        scope,
        rootOrgUnitId: readOptionalFormField(formData, "rootOrgUnitId"),
        confirmImpact: readOptionalFormField(formData, "confirmImpact"),
      };
    case "tenant":
      return {
        scope,
        confirmImpact: readOptionalFormField(formData, "confirmImpact"),
      };
    default:
      return { scope };
  }
};

const currentSelectedAvailability = async (
  context: AuthorizedAvailabilityContext,
): Promise<Extract<
  BadgeRulePlacementAvailabilityRecord,
  { readonly scope: "selected_courses" }
> | null> => {
  const current = await findBadgeRulePlacementAvailability(context.db, {
    tenantId: context.rule.tenantId,
    ruleId: context.rule.id,
  });
  return current?.scope === "selected_courses" ? current : null;
};

/** Registers the owner/admin course-availability workflow for stable badge-rule identities. */
export const registerTenantBadgeRuleAvailabilityAdminRoutes = (
  input: RegisterTenantBadgeRuleAvailabilityAdminRoutesInput,
): void => {
  const { app } = input;

  app.get("/tenants/:tenantId/admin/rules/:ruleId/availability", async (c) => {
    const pathParams = parseBadgeRulePlacementAvailabilityPathParams(c.req.param());
    c.header("Cache-Control", "no-store");
    const context = await loadAuthorizedAvailabilityContext(c, { ...input, ...pathParams });

    if (context instanceof Response) {
      return context;
    }

    let query: ReturnType<typeof parseBadgeRulePlacementAvailabilitySearchQuery>;

    try {
      query = parseBadgeRulePlacementAvailabilitySearchQuery(c.req.query());
    } catch {
      return c.json({ error: "Choose an LMS connection and enter a shorter course search." }, 400);
    }

    return renderAvailabilityPage(c, {
      routes: input,
      context,
      searchConnectionId: query.connectionId,
      searchQuery: query.q,
    });
  });

  app.post("/tenants/:tenantId/admin/rules/:ruleId/availability/update", async (c) => {
    const pathParams = parseBadgeRulePlacementAvailabilityPathParams(c.req.param());
    c.header("Cache-Control", "no-store");
    const context = await loadAuthorizedAvailabilityContext(c, { ...input, ...pathParams });

    if (context instanceof Response) {
      return context;
    }

    let request: ReturnType<typeof parseUpdateBadgeRulePlacementAvailabilityAdminRequest>;

    try {
      request = parseUpdateBadgeRulePlacementAvailabilityAdminRequest(
        mapScopeFormRequest(await c.req.formData()),
      );
    } catch {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message: "Choose a complete availability option and confirm its impact.",
      });
    }

    if (request.scope === "selected_courses") {
      const current = await currentSelectedAvailability(context);
      const postedIds = [...request.courseContextIds].sort();
      const currentIds = [...(current?.courseContextIds ?? [])].sort();

      if (
        current === null ||
        postedIds.length !== currentIds.length ||
        postedIds.some((id, index) => id !== currentIds[index])
      ) {
        return redirectToAvailability(c, {
          ...pathParams,
          userId: context.principal.userId,
          tone: "error",
          message: "The selected course list changed. Refresh the page and review it again.",
        });
      }
    }

    if (request.scope === "org_unit_subtree") {
      const [root, contexts, orgUnits] = await Promise.all([
        findTenantOrgUnitById(context.db, pathParams.tenantId, request.rootOrgUnitId),
        listTenantLmsCourseContexts(context.db, { tenantId: pathParams.tenantId }),
        listTenantOrgUnits(context.db, { tenantId: pathParams.tenantId }),
      ]);

      if (
        root === null ||
        !root.isActive ||
        !["institution", "college", "department", "program"].includes(root.unitType)
      ) {
        return redirectToAvailability(c, {
          ...pathParams,
          userId: context.principal.userId,
          tone: "error",
          message: "Choose an active organizational area and review its reach.",
        });
      }

      countCoursesWithinRoot(contexts, root.id, orgUnits);
    }

    if (request.scope === "tenant") {
      await listTenantLmsCourseContexts(context.db, { tenantId: pathParams.tenantId });
    }

    const availability: ReplaceBadgeRulePlacementAvailabilityRequest =
      request.scope === "selected_courses"
        ? { scope: request.scope, courseContextIds: request.courseContextIds }
        : request.scope === "org_unit_subtree"
          ? { scope: request.scope, rootOrgUnitId: request.rootOrgUnitId }
          : { scope: request.scope };
    const outcome = await replaceAvailability(context, availability);

    return redirectToAvailability(c, {
      ...pathParams,
      userId: context.principal.userId,
      ...outcome,
    });
  });

  app.post("/tenants/:tenantId/admin/rules/:ruleId/availability/courses", async (c) => {
    const pathParams = parseBadgeRulePlacementAvailabilityPathParams(c.req.param());
    c.header("Cache-Control", "no-store");
    const context = await loadAuthorizedAvailabilityContext(c, { ...input, ...pathParams });

    if (context instanceof Response) {
      return context;
    }

    let request: ReturnType<typeof parseAddBadgeRulePlacementAvailabilityCourseAdminRequest>;

    try {
      const formData = await c.req.formData();
      request = parseAddBadgeRulePlacementAvailabilityCourseAdminRequest({
        connectionId: readOptionalFormField(formData, "connectionId"),
        courseId: readOptionalFormField(formData, "courseId"),
      });
    } catch {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message: "Search again and choose a current LMS course.",
      });
    }

    const course = await resolveExactCourse(c, {
      service: input.lmsCourseAuthoring,
      context,
      ...request,
    });

    if (course === null || "status" in course) {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message: courseResolutionError(course),
      });
    }

    const courseContext = await upsertCatalogLmsCourseContext(context.db, {
      tenantId: pathParams.tenantId,
      lmsConnectionId: request.connectionId,
      contextId: course.courseId,
      displayName: course.title,
      courseCode: course.courseCode,
      createdByUserId: context.principal.userId,
    });
    const current = await currentSelectedAvailability(context);
    const courseContextIds = [...new Set([...(current?.courseContextIds ?? []), courseContext.id])];
    const outcome = await replaceAvailability(context, {
      scope: "selected_courses",
      courseContextIds,
    });

    return redirectToAvailability(c, {
      ...pathParams,
      userId: context.principal.userId,
      ...outcome,
      ...(outcome.tone === "success"
        ? { message: `Added ${course.title} to selected courses.` }
        : {}),
    });
  });

  app.post("/tenants/:tenantId/admin/rules/:ruleId/availability/courses/remove", async (c) => {
    const pathParams = parseBadgeRulePlacementAvailabilityPathParams(c.req.param());
    c.header("Cache-Control", "no-store");
    const context = await loadAuthorizedAvailabilityContext(c, { ...input, ...pathParams });

    if (context instanceof Response) {
      return context;
    }

    let request: ReturnType<typeof parseRemoveBadgeRulePlacementAvailabilityCourseAdminRequest>;

    try {
      const formData = await c.req.formData();
      request = parseRemoveBadgeRulePlacementAvailabilityCourseAdminRequest({
        courseContextId: readOptionalFormField(formData, "courseContextId"),
      });
    } catch {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message: "The selected course could not be removed. Refresh the page and try again.",
      });
    }

    const current = await currentSelectedAvailability(context);

    if (current === null || !current.courseContextIds.includes(request.courseContextId)) {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message:
          "That course is no longer in the selected list. Refresh the page to see current availability.",
      });
    }

    const remainingIds = current.courseContextIds.filter((id) => id !== request.courseContextId);

    if (remainingIds.length === 0) {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message:
          "Use Stop offering in courses to remove the final selected course and its availability policy.",
      });
    }

    const outcome = await replaceAvailability(context, {
      scope: "selected_courses",
      courseContextIds: remainingIds,
    });
    return redirectToAvailability(c, {
      ...pathParams,
      userId: context.principal.userId,
      ...outcome,
      ...(outcome.tone === "success" ? { message: "Course removed from the selected list." } : {}),
    });
  });

  app.post("/tenants/:tenantId/admin/rules/:ruleId/availability/course-mappings", async (c) => {
    const pathParams = parseBadgeRulePlacementAvailabilityPathParams(c.req.param());
    c.header("Cache-Control", "no-store");
    const context = await loadAuthorizedAvailabilityContext(c, { ...input, ...pathParams });

    if (context instanceof Response) {
      return context;
    }

    let request: ReturnType<typeof parseMapBadgeRulePlacementAvailabilityCourseAdminRequest>;

    try {
      const formData = await c.req.formData();
      request = parseMapBadgeRulePlacementAvailabilityCourseAdminRequest({
        connectionId: readOptionalFormField(formData, "connectionId"),
        courseId: readOptionalFormField(formData, "courseId"),
        parentOrgUnitId: readOptionalFormField(formData, "parentOrgUnitId"),
      });
    } catch {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message: "Choose a current LMS course and an active department or program.",
      });
    }

    const [course, parent] = await Promise.all([
      resolveExactCourse(c, {
        service: input.lmsCourseAuthoring,
        context,
        connectionId: request.connectionId,
        courseId: request.courseId,
      }),
      findTenantOrgUnitById(context.db, pathParams.tenantId, request.parentOrgUnitId),
    ]);

    if (course === null || "status" in course) {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message: courseResolutionError(course),
      });
    }

    if (
      parent === null ||
      !parent.isActive ||
      (parent.unitType !== "department" && parent.unitType !== "program")
    ) {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message: "Choose an active department or program for this course.",
      });
    }

    const courseContext = await upsertCatalogLmsCourseContext(context.db, {
      tenantId: pathParams.tenantId,
      lmsConnectionId: request.connectionId,
      contextId: course.courseId,
      displayName: course.title,
      courseCode: course.courseCode,
      createdByUserId: context.principal.userId,
    });

    if (courseContext.courseOrgUnitId !== null) {
      const existingOrgUnit = await findTenantOrgUnitById(
        context.db,
        pathParams.tenantId,
        courseContext.courseOrgUnitId,
      );

      if (existingOrgUnit?.parentOrgUnitId !== parent.id) {
        return redirectToAvailability(c, {
          ...pathParams,
          userId: context.principal.userId,
          tone: "error",
          message:
            "This LMS course is already mapped elsewhere. Review its current organization before changing it.",
        });
      }

      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "success",
        message: `${course.title} is already mapped to ${parent.displayName}.`,
      });
    }

    const ensured = await ensureExternalCourseOrgUnit(context.db, {
      tenantId: pathParams.tenantId,
      parentOrgUnitId: parent.id,
      externalSystemId: request.connectionId,
      externalCourseId: course.courseId,
      courseTitle: course.title,
      createdByUserId: context.principal.userId,
    });

    if (ensured.status === "invalid_parent") {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message: "That department or program is no longer active. Choose another area.",
      });
    }

    if (ensured.status === "slug_conflict") {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message:
          "This LMS course conflicts with an existing organization record. Ask an administrator to review the mapping.",
      });
    }

    const assigned = await assignLmsCourseContextOrgUnit(context.db, {
      tenantId: pathParams.tenantId,
      courseContextId: courseContext.id,
      courseOrgUnitId: ensured.orgUnit.id,
    });

    if (assigned.status !== "assigned" && assigned.status !== "unchanged") {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message:
          assigned.status === "mapping_conflict"
            ? "This LMS course was mapped elsewhere while you were working. Refresh the page and review the current mapping."
            : "The course mapping could not be saved. Refresh the page and try again.",
      });
    }

    if (assigned.status === "assigned") {
      await createAuditLog(context.db, {
        tenantId: pathParams.tenantId,
        actorUserId: context.principal.userId,
        action: "lms.course_context.org_unit_assigned",
        targetType: "tenant_lms_course_context",
        targetId: assigned.courseContext.id,
        metadata: {
          actorRole: context.membershipRole,
          parentOrgUnitId: parent.id,
          courseOrgUnitId: ensured.orgUnit.id,
          lmsConnectionId: request.connectionId,
        },
      });
    }

    return redirectToAvailability(c, {
      ...pathParams,
      userId: context.principal.userId,
      tone: "success",
      message: `Mapped ${course.title} to ${parent.displayName}.`,
    });
  });

  app.post("/tenants/:tenantId/admin/rules/:ruleId/availability/remove", async (c) => {
    const pathParams = parseBadgeRulePlacementAvailabilityPathParams(c.req.param());
    c.header("Cache-Control", "no-store");
    const context = await loadAuthorizedAvailabilityContext(c, { ...input, ...pathParams });

    if (context instanceof Response) {
      return context;
    }

    try {
      const formData = await c.req.formData();
      parseRemoveBadgeRulePlacementAvailabilityAdminRequest({
        confirmRemoval: readOptionalFormField(formData, "confirmRemoval"),
      });
    } catch {
      return redirectToAvailability(c, {
        ...pathParams,
        userId: context.principal.userId,
        tone: "error",
        message: "Confirm that faculty should no longer be able to add this rule to courses.",
      });
    }

    const result = await removeBadgeRulePlacementAvailability(context.db, {
      tenantId: pathParams.tenantId,
      ruleId: pathParams.ruleId,
      actorUserId: context.principal.userId,
      actorRole: context.membershipRole,
    });
    const outcome =
      result.status === "removed"
        ? { tone: "success" as const, message: "The rule is no longer offered in courses." }
        : result.status === "unchanged"
          ? { tone: "success" as const, message: "The rule was already unavailable to courses." }
          : result.status === "not_authorized"
            ? {
                tone: "error" as const,
                message:
                  "Only institution owners and administrators can remove course availability.",
              }
            : { tone: "error" as const, message: "This badge rule could not be found." };

    return redirectToAvailability(c, {
      ...pathParams,
      userId: context.principal.userId,
      ...outcome,
    });
  });
};
