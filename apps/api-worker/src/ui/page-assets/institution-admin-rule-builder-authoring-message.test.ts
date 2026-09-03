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
  readonly referenceId: string;
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

  it.each<AuthoringOperation>([
    "create_draft",
    "create_and_submit",
    "save_new_draft_version",
    "save_and_submit",
  ])("renders the safe $operation recovery policy", (operation) => {
    expect(
      unconfirmedMessage({
        operation,
        referenceId: "brd_42",
      }),
    ).toBe(
      "CredTrail could not confirm this save after checking automatically. It is safe to try again: CredTrail will reuse the same save identity instead of creating another rule or version. If the problem continues, contact support with reference brd_42.",
    );
  });
});
