export const logLtiWarning = (
  message: string,
  context: Record<string, string | number | boolean>,
): void => {
  console.error(`[lti] ${message}`, context);
};
