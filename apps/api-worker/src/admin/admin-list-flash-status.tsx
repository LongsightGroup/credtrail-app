import type { InstitutionAdminListFlashWorkspace } from "./institution-admin/list-flash-workspace";
import { AdminStatus } from "./components";

export const AdminListFlashStatus = (
  workspace: InstitutionAdminListFlashWorkspace | null | undefined,
): ReturnType<typeof AdminStatus> | null => {
  if (
    workspace?.listError !== null &&
    workspace?.listError !== undefined &&
    workspace.listError.length > 0
  ) {
    return <AdminStatus tone="error">{workspace.listError}</AdminStatus>;
  }

  if (
    workspace?.listNotice !== null &&
    workspace?.listNotice !== undefined &&
    workspace.listNotice.length > 0
  ) {
    return <AdminStatus tone="success">{workspace.listNotice}</AdminStatus>;
  }

  return null;
};
