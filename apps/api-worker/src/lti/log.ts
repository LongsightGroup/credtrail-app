import type { AppContext } from "../app";
import { optionalAppLogger, type AppLogger } from "../app/observability";

export const ltiLogger = (c: AppContext): AppLogger | undefined => {
  return optionalAppLogger(c)?.child({ component: "lti" });
};
