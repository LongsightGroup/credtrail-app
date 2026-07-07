import type { AdminListMessageWorkspace } from "./admin-list-message-flash";
import { setAdminListMessageFlash } from "./admin-list-message-flash";
import type { AppContext } from "../app";

export const redirectWithAdminListFlash = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    workspace: AdminListMessageWorkspace;
    path: string;
    tone: "success" | "error";
    message: string;
  },
): Promise<Response> => {
  await setAdminListMessageFlash(c, {
    tenantId: input.tenantId,
    userId: input.userId,
    workspace: input.workspace,
    tone: input.tone,
    message: input.message,
  });

  return c.redirect(input.path, 303);
};
