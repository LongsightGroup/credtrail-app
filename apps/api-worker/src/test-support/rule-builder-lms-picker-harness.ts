import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import {
  FakeElement,
  FakeInput,
  FakeOption,
  FakeSelect,
  type FakeTimers,
} from "./browser-page-asset-harness";

/** Observable completion states returned by the LMS picker page asset. */
export type LmsLookupOutcome =
  | { readonly status: "complete" }
  | { readonly status: "superseded" }
  | {
      readonly status: "failed";
      readonly source: "courses" | "gradebook-items" | "workflow-states";
      readonly message: string;
    };

/** Browser-facing operations exercised by rule-builder LMS picker tests. */
export interface RuleBuilderLmsPickerHarness {
  readonly bindDebouncedSearch: (input: {
    readonly debounceMs: number;
    readonly onInput: () => Promise<unknown>;
    readonly searchInput: FakeInput;
  }) => () => void;
  readonly hydrateCourseSelect: (
    card: object,
    select: FakeSelect,
    query: string,
  ) => Promise<LmsLookupOutcome>;
  readonly hydrateGradebookItemSelect: (input: {
    readonly itemSelect: FakeSelect;
    readonly itemsUrl: string;
    readonly query: string;
    readonly fallbackMessage: string;
  }) => Promise<LmsLookupOutcome>;
  readonly hydrateGradebookItemsForCard: (
    card: FakeElement,
    query: string,
  ) => Promise<LmsLookupOutcome>;
  readonly hydrateWorkflowStateSelect: (input: {
    readonly stateSelect: FakeSelect;
    readonly workflowStatesUrl: string;
    readonly fallbackMessage: string;
  }) => Promise<LmsLookupOutcome>;
  readonly readConditionFromCard: (card: FakeElement, strict: boolean) => unknown;
  readonly renderConditionFields: (card: FakeElement, seed: object) => void;
  readonly reportedErrors: readonly unknown[];
  readonly setSelectedLmsConnectionId: (connectionId: string) => void;
}

type RuntimePickerHarness = Omit<RuleBuilderLmsPickerHarness, "setSelectedLmsConnectionId">;

interface LoadPickerHarnessInput {
  readonly fetchImpl: typeof fetch;
  readonly timers?: FakeTimers;
}

/** Condition-card DOM nodes used to assert rendered rule-builder behavior. */
export interface RuleBuilderConditionCardFixture {
  readonly card: FakeElement;
  readonly fields: FakeElement;
  readonly summary: FakeElement;
}

/** Course-picker DOM nodes used to assert lookup behavior and status messages. */
export interface CourseLookupFixture {
  readonly card: FakeElement;
  readonly select: FakeSelect;
  readonly status: FakeElement;
}

/** Assignment-picker DOM nodes used to assert cascading lookup behavior. */
export interface AssignmentLookupFixture {
  readonly card: FakeElement;
  readonly itemSelect: FakeSelect;
  readonly stateSelect: FakeSelect;
  readonly status: FakeElement;
}

const pickerAssetSource = (): string => {
  const sourceNames = [
    "institution-admin-rule-builder-course-labels.js",
    "institution-admin-rule-builder-condition-fields.js",
    "institution-admin-rule-builder-condition-field-renderers.js",
    "lms-picker-payload-parsers.js",
    "lms-gradebook-picker-primitives.js",
    "institution-admin-rule-builder-lms-picker.js",
    "institution-admin-rule-builder-condition-model.js",
    "institution-admin-rule-builder-summary.js",
  ];
  const sources = sourceNames.map((sourceName) =>
    readFileSync(new URL(`../ui/page-assets/content/js/${sourceName}`, import.meta.url), "utf8"),
  );
  sources.push(
    "globalThis.__pickerHarness = { bindDebouncedSearch: lmsBindDebouncedSearch, hydrateCourseSelect, hydrateGradebookItemSelect: lmsHydrateGradebookItemSelect, hydrateGradebookItemsForCard: hydrateGradebookItemSelect, hydrateWorkflowStateSelect: lmsHydrateWorkflowStateSelect, readConditionFromCard, renderConditionFields, reportedErrors };",
  );
  return sources.join("\n");
};

const isRuntimePickerHarness = (value: unknown): value is RuntimePickerHarness => {
  if (value === null || typeof value !== "object") {
    return false;
  }

  const functionNames = [
    "bindDebouncedSearch",
    "hydrateCourseSelect",
    "hydrateGradebookItemSelect",
    "hydrateGradebookItemsForCard",
    "hydrateWorkflowStateSelect",
    "readConditionFromCard",
    "renderConditionFields",
  ];

  return (
    functionNames.every((functionName) => typeof Reflect.get(value, functionName) === "function") &&
    Array.isArray(Reflect.get(value, "reportedErrors"))
  );
};

/** Loads the production picker fragments into a deterministic fake-browser runtime. */
export const loadRuleBuilderLmsPickerHarness = (
  input: LoadPickerHarnessInput,
): RuleBuilderLmsPickerHarness => {
  const reportedErrors: unknown[] = [];
  let selectedLmsConnectionId = "connection-1";
  const context = createContext({
    AbortController,
    AbortSignal,
    Error,
    HTMLButtonElement: class {},
    HTMLInputElement: FakeInput,
    HTMLSelectElement: FakeSelect,
    HTMLTemplateElement: class {},
    HTMLTextAreaElement: class {},
    HTMLElement: FakeElement,
    Map,
    Promise,
    Set,
    URLSearchParams,
    WeakMap,
    document: {
      createElement: (tagName: string): FakeElement => {
        if (tagName === "input") {
          return new FakeInput();
        }

        if (tagName === "option") {
          return new FakeOption();
        }

        if (tagName === "select") {
          return new FakeSelect();
        }

        return new FakeElement(tagName.toUpperCase());
      },
    },
    encodeURIComponent,
    fetch: input.fetchImpl,
    bindExclusiveFieldPair: (): void => undefined,
    conditionTypeLabels: {},
    getDefaultCourseId: (): string => "",
    getSelectedLmsConnectionId: (): string => selectedLmsConnectionId,
    lmsConnectionsApiPath: "/v1/lms/connections",
    reportError: (error: unknown): void => {
      reportedErrors.push(error);
    },
    reportedErrors,
    ruleBuilderConditionList: new FakeElement(),
    ruleValueLists: [],
    window: {
      clearTimeout: input.timers?.clearTimeout ?? clearTimeout,
      setTimeout: input.timers?.setTimeout ?? setTimeout,
    },
  });

  new Script(pickerAssetSource()).runInContext(context);
  const runtimeHarness: unknown = context.__pickerHarness;

  if (!isRuntimePickerHarness(runtimeHarness)) {
    throw new TypeError("Rule-builder LMS picker harness did not initialize.");
  }

  return {
    ...runtimeHarness,
    setSelectedLmsConnectionId: (connectionId): void => {
      selectedLmsConnectionId = connectionId;
    },
  };
};

/** Creates one condition card with the native controls used by production renderers. */
export const createRuleBuilderConditionCard = (
  conditionType: string,
): RuleBuilderConditionCardFixture => {
  const card = new FakeElement();
  card.className = "ct-admin__condition-card";
  const typeSelect = new FakeSelect();
  typeSelect.className = "ct-admin__condition-type";
  typeSelect.value = conditionType;
  const negate = new FakeInput();
  negate.dataset.field = "negate";
  const fields = new FakeElement();
  fields.className = "ct-admin__condition-fields";
  const summary = new FakeElement();
  summary.className = "ct-admin__condition-summary";
  card.append(typeSelect, negate, fields, summary);
  return { card, fields, summary };
};

/** Creates one standalone course lookup fixture. */
export const createCourseLookupFixture = (fieldName = "courseId"): CourseLookupFixture => {
  const card = new FakeElement();
  const select = new FakeSelect();
  select.dataset.field = fieldName;
  const status = new FakeElement("P");
  status.setAttribute("data-lms-course-status", fieldName);
  status.hidden = true;
  card.append(select, status);
  return { card, select, status };
};

/** Creates one assignment lookup fixture with its dependent workflow-state control. */
export const createAssignmentLookupFixture = (): AssignmentLookupFixture => {
  const card = new FakeElement();
  const courseSelect = new FakeSelect();
  courseSelect.dataset.field = "courseId";
  courseSelect.value = "course-101";
  const itemSelect = new FakeSelect();
  itemSelect.dataset.field = "assignmentId";
  itemSelect.dataset.lmsGradebookItemSelect = "";
  const stateSelect = new FakeSelect();
  stateSelect.dataset.lmsWorkflowStateSelect = "";
  const status = new FakeElement("P");
  status.setAttribute("data-lms-gradebook-status", "");
  status.hidden = true;
  card.append(courseSelect, itemSelect, stateSelect, status);
  return { card, itemSelect, stateSelect, status };
};
