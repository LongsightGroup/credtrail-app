/** Serializes one validated queue payload for persistence. */
export const serializeQueuePayload = (payload: unknown): string => {
  if (payload === undefined) {
    throw new Error("Queue payload is not JSON serializable");
  }

  return JSON.stringify(payload);
};
