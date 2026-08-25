const requestRuleBuilderAuthoringCommand = async (dependencies, input) => {
  const replaySafeCreate = input.delivery.kind === "replay_safe_create";

  if (!replaySafeCreate && input.delivery.kind !== "single_attempt") {
    throw new Error("Unknown rule authoring delivery policy");
  }

  const maximumAttempts = replaySafeCreate ? 2 : 1;
  const payload = replaySafeCreate
    ? { ...input.payload, builderDraftId: input.delivery.builderDraftId }
    : input.payload;
  const body = JSON.stringify(payload);

  for (let attemptCount = 1; attemptCount <= maximumAttempts; attemptCount += 1) {
    const requestId = dependencies.createRequestId();

    try {
      const response = await dependencies.request(input.apiPath, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-request-id": requestId,
        },
        body,
      });

      return {
        status: "response_received",
        response,
        requestId,
        attemptCount,
      };
    } catch {
      if (attemptCount === maximumAttempts) {
        return {
          status: "unconfirmed",
          requestId,
          attemptCount,
        };
      }
    }
  }

  throw new Error("Rule authoring attempt limit was not resolved");
};

const ruleBuilderUnconfirmedAuthoringMessage = (input) => {
  let nextStep;

  if (input.operation === "create_draft") {
    nextStep = "If it is not listed, try creating the draft again.";
  } else if (input.operation === "create_and_submit") {
    nextStep = "If it is not listed, try creating and submitting it again.";
  } else if (input.operation === "save_new_draft_version") {
    nextStep = "If the latest draft is unchanged, try saving again.";
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
  let state = "idle";

  const execute = async (input) => {
    if (state !== "idle") {
      return { status: "ignored" };
    }

    state = "submitting";

    try {
      const requestResult = await requestRuleBuilderAuthoringCommand(dependencies, input);

      if (requestResult.status === "unconfirmed") {
        return {
          status: "unknown",
          requestId: requestResult.requestId,
          attemptCount: requestResult.attemptCount,
        };
      }

      let payload;

      try {
        payload = await dependencies.parseResponse(requestResult.response);
      } catch {
        return {
          status: "unknown",
          requestId: requestResult.requestId,
          attemptCount: requestResult.attemptCount,
        };
      }

      if (!requestResult.response.ok) {
        return {
          status: "rejected",
          message: dependencies.errorMessage(payload),
        };
      }

      const outcome =
        payload && typeof payload === "object" && typeof payload.outcome === "string"
          ? payload.outcome
          : "";

      if (outcome !== "draft_saved" && outcome !== "pending_approval" && outcome !== "approved") {
        return {
          status: "rejected",
          message: "CredTrail returned an invalid rule authoring outcome.",
        };
      }

      state = "completed";
      return {
        status: "completed",
        outcome,
      };
    } finally {
      if (state === "submitting") {
        state = "idle";
      }
    }
  };

  return {
    execute,
    state: () => state,
  };
};
