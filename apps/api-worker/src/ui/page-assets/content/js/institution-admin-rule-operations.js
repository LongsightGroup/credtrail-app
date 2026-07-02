const loadAssertionLifecycle = async (
  assertionId,
  statusElement,
  outputElement = assertionLifecycleOutput,
) => {
  const normalizedAssertionId = typeof assertionId === "string" ? assertionId.trim() : "";

  if (normalizedAssertionId.length === 0) {
    if (statusElement instanceof HTMLElement) {
      setStatus(statusElement, "Assertion ID is required.", true);
    }

    return null;
  }

  if (statusElement instanceof HTMLElement) {
    setStatus(statusElement, "Loading lifecycle state...", false);
  }

  setCodeOutput(outputElement, "");

  try {
    const response = await fetch(
      assertionsApiPathPrefix + "/" + encodeURIComponent(normalizedAssertionId) + "/lifecycle",
    );
    const payload = await parseJsonBody(response);

    if (!response.ok) {
      if (statusElement instanceof HTMLElement) {
        setStatus(statusElement, errorDetailFromPayload(payload), true);
      }

      return null;
    }

    const state = payload && typeof payload.state === "string" ? payload.state : "unknown";
    const source = payload && typeof payload.source === "string" ? payload.source : "unknown";
    const eventCount = payload && Array.isArray(payload.events) ? payload.events.length : 0;

    if (statusElement instanceof HTMLElement) {
      setStatus(
        statusElement,
        "Lifecycle loaded: state=" +
          state +
          ", source=" +
          source +
          ", events=" +
          String(eventCount) +
          ".",
        false,
      );
    }

    setCodeOutput(outputElement, JSON.stringify(payload, null, 2));
    fillLifecycleAssertionIdInputs(normalizedAssertionId);
    return payload;
  } catch {
    if (statusElement instanceof HTMLElement) {
      setStatus(statusElement, "Unable to load lifecycle state from this browser session.", true);
    }

    return null;
  }
};
const transitionAssertionLifecycle = async ({
  assertionId,
  toState,
  reasonCode,
  reason,
  statusElement,
}) => {
  const normalizedAssertionId = typeof assertionId === "string" ? assertionId.trim() : "";
  const normalizedToState = typeof toState === "string" ? toState.trim() : "";
  const normalizedReasonCode = typeof reasonCode === "string" ? reasonCode.trim() : "";
  const normalizedReason = typeof reason === "string" ? reason.trim() : "";

  if (
    normalizedAssertionId.length === 0 ||
    normalizedToState.length === 0 ||
    normalizedReasonCode.length === 0
  ) {
    if (statusElement instanceof HTMLElement) {
      setStatus(statusElement, "Assertion, target state, and reason code are required.", true);
    }

    return null;
  }

  if (statusElement instanceof HTMLElement) {
    setStatus(statusElement, "Applying lifecycle transition...", false);
  }

  try {
    const response = await fetch(
      assertionsApiPathPrefix +
        "/" +
        encodeURIComponent(normalizedAssertionId) +
        "/lifecycle/transition",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          toState: normalizedToState,
          reasonCode: normalizedReasonCode,
          ...(normalizedReason.length > 0 ? { reason: normalizedReason } : {}),
        }),
      },
    );
    const payload = await parseJsonBody(response);

    if (!response.ok) {
      if (statusElement instanceof HTMLElement) {
        setStatus(statusElement, errorDetailFromPayload(payload), true);
      }

      return null;
    }

    const status = payload && typeof payload.status === "string" ? payload.status : "updated";
    const currentState =
      payload && typeof payload.currentState === "string"
        ? payload.currentState
        : normalizedToState;

    if (statusElement instanceof HTMLElement) {
      setStatus(
        statusElement,
        "Lifecycle transition result: status=" + status + ", currentState=" + currentState + ".",
        false,
      );
    }

    return payload;
  } catch {
    if (statusElement instanceof HTMLElement) {
      setStatus(
        statusElement,
        "Unable to apply lifecycle transition from this browser session.",
        true,
      );
    }

    return null;
  }
};
