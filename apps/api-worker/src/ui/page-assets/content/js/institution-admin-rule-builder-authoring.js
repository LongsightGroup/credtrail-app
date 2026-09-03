const RULE_BUILDER_AUTHORING_REQUEST_TIMEOUT_MS = 15_000;
const RULE_BUILDER_RECONCILIATION_REQUEST_TIMEOUT_MS = 5_000;
const RULE_BUILDER_RECONCILIATION_DELAYS_MS = [250, 750];
const RULE_BUILDER_FINAL_RECONCILIATION_DELAYS_MS = [500, 1_000, 2_000];

const ruleBuilderCompletedAuthoringResult = (payload) => {
  const outcome =
    payload && typeof payload === "object" && typeof payload.outcome === "string"
      ? payload.outcome
      : "";
  const ruleId =
    payload && typeof payload === "object" && typeof payload.ruleId === "string"
      ? payload.ruleId
      : payload &&
          typeof payload === "object" &&
          payload.rule &&
          typeof payload.rule === "object" &&
          typeof payload.rule.id === "string"
        ? payload.rule.id
        : "";
  const versionId =
    payload && typeof payload === "object" && typeof payload.versionId === "string"
      ? payload.versionId
      : payload &&
          typeof payload === "object" &&
          payload.version &&
          typeof payload.version === "object" &&
          typeof payload.version.id === "string"
        ? payload.version.id
        : "";

  if (
    (outcome !== "draft_saved" && outcome !== "pending_approval" && outcome !== "approved") ||
    ruleId.length === 0 ||
    versionId.length === 0
  ) {
    return null;
  }

  return {
    status: "completed",
    outcome,
    ruleId,
    versionId,
  };
};

const attemptRuleBuilderAuthoringCommand = async (dependencies, input) => {
  const requestId = dependencies.createRequestId();
  const request = dependencies.request;
  let response;

  try {
    response = await request(input.apiPath, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-request-id": requestId,
      },
      body: input.body,
      signal: AbortSignal.timeout(
        dependencies.requestTimeoutMs ?? RULE_BUILDER_AUTHORING_REQUEST_TIMEOUT_MS,
      ),
    });
  } catch (error) {
    dependencies.reportUnexpectedError(error);
    return {
      status: "unknown",
      requestId,
      attemptCount: input.attemptCount,
    };
  }

  let payload;

  try {
    payload = await dependencies.parseResponse(response);
  } catch (error) {
    dependencies.reportUnexpectedError(error);
    return {
      status: "unknown",
      requestId,
      attemptCount: input.attemptCount,
    };
  }

  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && typeof payload.error === "string"
        ? payload.error
        : "";

    return message.length > 0
      ? { status: "rejected", message }
      : {
          status: "unknown",
          requestId,
          attemptCount: input.attemptCount,
        };
  }

  const completed = ruleBuilderCompletedAuthoringResult(payload);

  if (completed === null) {
    return {
      status: "unknown",
      requestId,
      attemptCount: input.attemptCount,
    };
  }

  return completed;
};

const checkRuleBuilderAuthoringResult = async (dependencies, resultApiPath) => {
  const requestId = dependencies.createRequestId();
  const request = dependencies.request;
  let response;

  try {
    response = await request(resultApiPath, {
      method: "GET",
      headers: {
        accept: "application/json",
        "x-request-id": requestId,
      },
      signal: AbortSignal.timeout(
        dependencies.reconciliationRequestTimeoutMs ??
          RULE_BUILDER_RECONCILIATION_REQUEST_TIMEOUT_MS,
      ),
    });
  } catch (error) {
    dependencies.reportUnexpectedError(error);
    return { status: "unavailable" };
  }

  let payload;

  try {
    payload = await dependencies.parseResponse(response);
  } catch (error) {
    dependencies.reportUnexpectedError(error);
    return { status: "unavailable" };
  }

  if (response.ok) {
    if (payload && typeof payload === "object" && payload.status === "pending") {
      return { status: "pending" };
    }

    return ruleBuilderCompletedAuthoringResult(payload) ?? { status: "unavailable" };
  }

  const message =
    payload && typeof payload === "object" && typeof payload.error === "string"
      ? payload.error
      : "";
  return message.length > 0
    ? { status: "rejected", message }
    : { status: "unavailable" };
};

const ruleBuilderAuthoringOperationForSubmit = (input) => {
  if (input.action === "save_draft") {
    return input.isEditMode ? "save_new_draft_version" : "create_draft";
  }

  if (input.action === "submit_for_approval") {
    return input.isEditMode ? "save_and_submit" : "create_and_submit";
  }

  throw new Error("Unknown rule authoring action");
};

const ruleBuilderUnconfirmedAuthoringMessage = (input) => {
  if (
    input.operation !== "create_draft" &&
    input.operation !== "create_and_submit" &&
    input.operation !== "save_new_draft_version" &&
    input.operation !== "save_and_submit"
  ) {
    throw new Error("Unknown rule authoring operation");
  }

  return (
    "CredTrail could not confirm this save after checking automatically. " +
    "It is safe to try again: CredTrail will reuse the same save identity instead of creating " +
    "another rule or version. If the problem continues, contact support with reference " +
    input.referenceId +
    "."
  );
};

const createRuleBuilderAuthoringController = (dependencies) => {
  let state = "idle";

  const reconcileAfterDelays = async (resultApiPath, delays) => {
    for (const delayMs of delays) {
      await dependencies.waitBeforeReplay(delayMs);
      const result = await checkRuleBuilderAuthoringResult(dependencies, resultApiPath);

      if (result.status === "completed" || result.status === "rejected") {
        return result;
      }
    }

    return null;
  };

  const execute = async (input) => {
    if (state !== "idle") {
      return { status: "ignored" };
    }

    state = "submitting";

    try {
      const reconciled = input.delivery.kind === "reconciled";

      if (!reconciled && input.delivery.kind !== "single_attempt") {
        throw new Error("Unknown rule authoring delivery policy");
      }

      const payload = reconciled
        ? { ...input.payload, builderDraftId: input.delivery.builderDraftId }
        : input.payload;
      const body = JSON.stringify(payload);
      const firstAttempt = await attemptRuleBuilderAuthoringCommand(dependencies, {
        apiPath: input.apiPath,
        body,
        attemptCount: 1,
      });

      if (firstAttempt.status === "completed") {
        state = "completed";
        return firstAttempt;
      }

      if (firstAttempt.status === "rejected" || !reconciled) {
        return firstAttempt;
      }

      dependencies.onReconciliationStarted();
      const firstReconciliation = await reconcileAfterDelays(
        input.delivery.resultApiPath,
        RULE_BUILDER_RECONCILIATION_DELAYS_MS,
      );

      if (firstReconciliation !== null) {
        if (firstReconciliation.status === "completed") {
          state = "completed";
        }

        return firstReconciliation;
      }

      const replay = await attemptRuleBuilderAuthoringCommand(dependencies, {
        apiPath: input.apiPath,
        body,
        attemptCount: 2,
      });

      if (replay.status === "completed") {
        state = "completed";
        return replay;
      }

      if (replay.status === "rejected") {
        return replay;
      }

      const finalReconciliation = await reconcileAfterDelays(
        input.delivery.resultApiPath,
        RULE_BUILDER_FINAL_RECONCILIATION_DELAYS_MS,
      );

      if (finalReconciliation !== null) {
        if (finalReconciliation.status === "completed") {
          state = "completed";
        }

        return finalReconciliation;
      }

      return {
        status: "unknown",
        referenceId: input.delivery.builderDraftId,
        attemptCount: replay.attemptCount,
      };
    } finally {
      if (state === "submitting") {
        state = "idle";
      }
    }
  };

  return {
    execute,
    resetCompleted: () => {
      if (state === "completed") {
        state = "idle";
      }
    },
    state: () => state,
  };
};
