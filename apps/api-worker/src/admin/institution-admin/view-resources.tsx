import type { Child } from "hono/jsx";
import { serializeJsonScriptContent } from "../institution-admin-shell";
import { buildInstitutionAdminAccessViewResources } from "./access-view-resources";
import { buildInstitutionAdminHomeViewResources } from "./home-view-resources";
import type { InstitutionAdminPageInput, InstitutionAdminView } from "./page-types";
import {
  renderInstitutionAdminViewContent,
  type InstitutionAdminViewDefinition,
} from "./view-content";
import { buildInstitutionAdminViewOptionResources } from "./view-option-resources";
import type { buildInstitutionAdminViewPaths } from "./view-paths";
import {
  buildInstitutionAdminLearnerRecordViewResources,
  buildInstitutionAdminOperationsViewResources,
  buildInstitutionAdminReportingViewResources,
  buildInstitutionAdminRulesViewResources,
} from "./workspace-view-resources";

export interface BuildInstitutionAdminViewResourcesInput {
  input: InstitutionAdminPageInput;
  paths: ReturnType<typeof buildInstitutionAdminViewPaths>;
  view: InstitutionAdminView;
  viewDefinition: InstitutionAdminViewDefinition;
}

export interface InstitutionAdminViewResources {
  adminPageContextJson: string;
  viewContent: Child;
}

const adminPageContext = (
  view: InstitutionAdminView,
  paths: ReturnType<typeof buildInstitutionAdminViewPaths>,
): Record<string, string> => {
  if (view === "rules" || view === "operationsBadgeStatus") {
    return {
      badgeRuleApiPath: paths.badgeRuleApiPath,
      assertionsApiPathPrefix: paths.assertionsApiPathPrefix,
    };
  }

  if (view === "operationsIssuedBadges") {
    return {
      assertionsApiPathPrefix: paths.assertionsApiPathPrefix,
    };
  }

  return {};
};

export const buildInstitutionAdminViewResources = (
  resourceInput: BuildInstitutionAdminViewResourcesInput,
): InstitutionAdminViewResources => {
  const { input, paths, view, viewDefinition } = resourceInput;
  const builtView = viewDefinition.build?.({ input, paths });

  if (builtView !== undefined) {
    return {
      adminPageContextJson: serializeJsonScriptContent(builtView.adminPageContext),
      viewContent: builtView.viewContent,
    };
  }

  const options = buildInstitutionAdminViewOptionResources({
    page: input,
    dataNeeds: viewDefinition.dataNeeds,
  });
  const home =
    view === "home"
      ? buildInstitutionAdminHomeViewResources({ page: input, paths })
      : { workspaceCardsMarkup: <></> };
  const viewContent = renderInstitutionAdminViewContent({
    input,
    view,
    home,
    controls: options.controls,
    learnerRecords: buildInstitutionAdminLearnerRecordViewResources({
      page: input,
      paths,
      dataNeeds: viewDefinition.dataNeeds,
    }),
    operations: buildInstitutionAdminOperationsViewResources({
      page: input,
      dataNeeds: viewDefinition.dataNeeds,
    }),
    reporting: buildInstitutionAdminReportingViewResources({
      page: input,
      paths,
      view,
      dataNeeds: viewDefinition.dataNeeds,
    }),
    rules: buildInstitutionAdminRulesViewResources({
      page: input,
      paths,
      dataNeeds: viewDefinition.dataNeeds,
    }),
    access: buildInstitutionAdminAccessViewResources({
      page: input,
      paths,
      dataNeeds: viewDefinition.dataNeeds,
      options: options.access,
    }),
  });

  return {
    adminPageContextJson: serializeJsonScriptContent(adminPageContext(view, paths)),
    viewContent,
  };
};
