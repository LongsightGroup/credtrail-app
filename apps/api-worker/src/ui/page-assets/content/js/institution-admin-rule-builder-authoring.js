const RULE_BUILDER_AUTHORING_REQUEST_TIMEOUT_MS = 15_000;

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

  const outcome =
    payload && typeof payload === "object" && typeof payload.outcome === "string"
      ? payload.outcome
      : "";

  if (outcome !== "draft_saved" && outcome !== "pending_approval" && outcome !== "approved") {
    return {
      status: "unknown",
      requestId,
      attemptCount: input.attemptCount,
    };
  }

  return {
    status: "completed",
    outcome,
  };
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
  let nextStep;

  if (input.operation === "create_draft") {
    nextStep = "If it is not listed, try creating the draft again.";
  } else if (input.operation === "create_and_submit") {
    nextStep = "If it is not listed, try creating and submitting it again.";
  } else if (input.operation === "save_new_draft_version") {
    nextStep = "If the latest draft is unchanged, try saving again.";
  } else if (input.operation === "save_and_submit") {
    nextStep =
      "If the latest version is not pending approval or approved, try saving and submitting it again.";
  } else {
    throw new Error("Unknown rule authoring operation");
  }

  const confirmationMessage =
    input.attemptCount > 1
      ? "CredTrail retried but did not receive confirmation. "
      : "CredTrail did not receive confirmation. ";

  return (
    confirmationMessage +
    "In Rules, look for “" +
    input.ruleName +
    "”. " +
    nextStep +
    " Reference: " +
    input.requestId +
    "."
  );
};

const createRuleBuilderAuthoringController = (dependencies) => {
  const replayDelayMs = 250;
  let state = "idle";

  const execute = async (input) => {
    if (state !== "idle") {
      return { status: "ignored" };
    }

    state = "submitting";

    try {
      const replaySafeCreate = input.delivery.kind === "replay_safe_create";

      if (!replaySafeCreate && input.delivery.kind !== "single_attempt") {
        throw new Error("Unknown rule authoring delivery policy");
      }

      const maximumAttempts = replaySafeCreate ? 2 : 1;
      const payload = replaySafeCreate
        ? { ...input.payload, builderDraftId: input.delivery.builderDraftId }
        : input.payload;
      const body = JSON.stringify(payload);
      let attemptCount = 1;

      while (true) {
        const result = await attemptRuleBuilderAuthoringCommand(dependencies, {
          apiPath: input.apiPath,
          body,
          attemptCount,
        });

        if (result.status === "completed") {
          state = "completed";
          return result;
        }

        if (result.status === "rejected" || attemptCount === maximumAttempts) {
          return result;
        }

        await dependencies.waitBeforeReplay(replayDelayMs);
        attemptCount += 1;
      }
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
