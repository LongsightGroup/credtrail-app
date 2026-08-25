import { readFileSync } from "node:fs";
import { createContext, Script } from "node:vm";
import { describe, expect, it } from "vitest";

type AuthoringOperation = "create_draft" | "create_and_submit" | "save_new_draft_version";

type UnconfirmedAuthoringMessage = (input: {
  readonly operation: AuthoringOperation;
  readonly ruleName: string;
  readonly attemptCount: number;
  readonly requestId: string;
}) => string;

const loadUnconfirmedAuthoringMessage = (): UnconfirmedAuthoringMessage => {
  const source = readFileSync(
    new URL("./content/js/institution-admin-rule-builder-authoring.js", import.meta.url),
    "utf8",
  );
  const context = createContext({});
  new Script(
    `${source}\nthis.unconfirmedMessage = ruleBuilderUnconfirmedAuthoringMessage;`,
  ).runInContext(context);
  const unconfirmedMessage = (context as { readonly unconfirmedMessage?: unknown })
    .unconfirmedMessage;

  if (typeof unconfirmedMessage !== "function") {
    throw new Error("Rule builder unconfirmed message policy did not load");
  }

  // SAFETY: The VM source defines the function, and the runtime guard verifies its callable boundary.
  return unconfirmedMessage as UnconfirmedAuthoringMessage;
};

const unconfirmedAuthoringMessage = loadUnconfirmedAuthoringMessage();

describe("rule builder unconfirmed authoring message", () => {
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
  ])(
    "renders the $operation recovery policy",
    ({ operation, attemptCount, confirmationMessage, nextStep }) => {
      expect(
        unconfirmedAuthoringMessage({
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
