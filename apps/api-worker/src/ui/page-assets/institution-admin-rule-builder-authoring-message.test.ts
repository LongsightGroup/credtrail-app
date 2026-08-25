import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";

type AuthoringAction = "save_draft" | "submit_for_approval";

type AuthoringOperation =
  | "create_draft"
  | "create_and_submit"
  | "save_new_draft_version"
  | "save_and_submit";

type AuthoringOperationForSubmit = (input: {
  readonly isEditMode: boolean;
  readonly action: AuthoringAction;
}) => AuthoringOperation;

type UnconfirmedAuthoringMessage = (input: {
  readonly operation: AuthoringOperation;
  readonly ruleName: string;
  readonly attemptCount: number;
  readonly requestId: string;
}) => string;

const loadAuthoringPolicy = (): {
  readonly operationForSubmit: AuthoringOperationForSubmit;
  readonly unconfirmedMessage: UnconfirmedAuthoringMessage;
} => {
  const source = readFileSync(
    new URL("./content/js/institution-admin-rule-builder-authoring.js", import.meta.url),
    "utf8",
  );
  const context = createContext({});
  new Script(
    `${source}\nthis.operationForSubmit = ruleBuilderAuthoringOperationForSubmit; this.unconfirmedMessage = ruleBuilderUnconfirmedAuthoringMessage;`,
  ).runInContext(context);
  const loaded = context as {
    readonly operationForSubmit?: unknown;
    readonly unconfirmedMessage?: unknown;
  };

  if (
    typeof loaded.operationForSubmit !== "function" ||
    typeof loaded.unconfirmedMessage !== "function"
  ) {
    throw new Error("Rule builder authoring policy did not load");
  }

  // SAFETY: The VM source defines both functions, and the runtime guards verify their callable boundaries.
  return {
    operationForSubmit: loaded.operationForSubmit as AuthoringOperationForSubmit,
    unconfirmedMessage: loaded.unconfirmedMessage as UnconfirmedAuthoringMessage,
  };
};

const { operationForSubmit, unconfirmedMessage } = loadAuthoringPolicy();

describe("rule builder authoring policy", () => {
  it.each<{
    readonly isEditMode: boolean;
    readonly action: AuthoringAction;
    readonly operation: AuthoringOperation;
  }>([
    { isEditMode: false, action: "save_draft", operation: "create_draft" },
    { isEditMode: false, action: "submit_for_approval", operation: "create_and_submit" },
    { isEditMode: true, action: "save_draft", operation: "save_new_draft_version" },
    { isEditMode: true, action: "submit_for_approval", operation: "save_and_submit" },
  ])(
    "maps $isEditMode edit mode and $action to $operation",
    ({ isEditMode, action, operation }) => {
      expect(operationForSubmit({ isEditMode, action })).toBe(operation);
    },
  );

  it.each<{
    readonly operation: AuthoringOperation;
    readonly attemptCount: number;
    readonly confirmationMessage: string;
    readonly nextStep: string;
  }>([
    {
      operation: "create_draft",
      attemptCount: 2,
      confirmationMessage: "CredTrail retried but did not receive confirmation.",
      nextStep: "If it is not listed, try creating the draft again.",
    },
    {
      operation: "create_and_submit",
      attemptCount: 2,
      confirmationMessage: "CredTrail retried but did not receive confirmation.",
      nextStep: "If it is not listed, try creating and submitting it again.",
    },
    {
      operation: "save_new_draft_version",
      attemptCount: 1,
      confirmationMessage: "CredTrail did not receive confirmation.",
      nextStep: "If the latest draft is unchanged, try saving again.",
    },
    {
      operation: "save_and_submit",
      attemptCount: 1,
      confirmationMessage: "CredTrail did not receive confirmation.",
      nextStep:
        "If the latest version is not pending approval or approved, try saving and submitting it again.",
    },
  ])(
    "renders the $operation recovery policy",
    ({ operation, attemptCount, confirmationMessage, nextStep }) => {
      expect(
        unconfirmedMessage({
          operation,
          ruleName: "Attendance award",
          attemptCount,
          requestId: "request-42",
        }),
      ).toBe(
        `${confirmationMessage} In Rules, look for “Attendance award”. ${nextStep} Reference: request-42.`,
      );
    },
  );
});
