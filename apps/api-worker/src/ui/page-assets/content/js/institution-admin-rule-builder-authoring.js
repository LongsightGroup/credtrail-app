const createRuleBuilderAuthoringController = (dependencies) => {
  let state = "idle";

  const execute = async (input) => {
    if (state !== "idle") {
      return { status: "ignored" };
    }

    state = "submitting";
    const requestId = dependencies.createRequestId();
    const builderDraftId = input.payload.builderDraftId;
    const replaySafeCreate = typeof builderDraftId === "string" && builderDraftId.length > 0;
    const maximumAttempts = replaySafeCreate ? 2 : 1;
    const body = JSON.stringify(input.payload);

    for (let attempt = 1; attempt <= maximumAttempts; attempt += 1) {
      let response;

      try {
        response = await dependencies.request(input.apiPath, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-request-id": requestId,
          },
          body,
        });
      } catch {
        if (attempt < maximumAttempts) {
          continue;
        }

        state = "idle";
        return {
          status: "unknown",
          requestId,
          retryAttempted: attempt > 1,
        };
      }

      try {
        const payload = await dependencies.parseResponse(response);

        if (!response.ok) {
          state = "idle";
          return {
            status: "rejected",
            message: dependencies.errorMessage(payload),
          };
        }

        const outcome =
          payload && typeof payload === "object" && typeof payload.outcome === "string"
            ? payload.outcome
            : "";

        if (
          outcome !== "draft_saved" &&
          outcome !== "pending_approval" &&
          outcome !== "approved"
        ) {
          state = "idle";
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
      } catch {
        state = "idle";
        return {
          status: "unknown",
          requestId,
          retryAttempted: attempt > 1,
        };
      }
    }

    throw new Error("Rule authoring attempt limit was not resolved");
  };

  return {
    execute,
    state: () => state,
  };
};
