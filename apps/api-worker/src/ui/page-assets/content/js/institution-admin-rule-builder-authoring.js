const createRuleBuilderAuthoringController = (dependencies) => {
  let state = "idle";

  const execute = async (input) => {
    if (state !== "idle") {
      return { status: "ignored" };
    }

    state = "submitting";

    try {
      const response = await dependencies.request(input.apiPath, {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify(input.payload),
      });
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
      return { status: "unknown" };
    }
  };

  return {
    execute,
    state: () => state,
  };
};
