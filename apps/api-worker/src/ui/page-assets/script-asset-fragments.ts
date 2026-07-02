import { renderAdminStatusPillClassBrowserHelper } from "../../admin/admin-status-pill-class";

export type ScriptPageAssetSource =
  | string
  | {
      readonly sourceName: string;
      readonly body: string;
    };

export type ScriptPageAssetSourceReader = (sourcePath: string) => string;

export const scriptPageAssetSourceName = (source: ScriptPageAssetSource): string => {
  return typeof source === "string" ? source : source.sourceName;
};

export const readScriptPageAssetSource = (
  source: ScriptPageAssetSource,
  readSource: ScriptPageAssetSourceReader,
): string => {
  return typeof source === "string" ? readSource(source) : source.body;
};

export const ADMIN_STATUS_PILL_CLASS_SCRIPT_SOURCE: ScriptPageAssetSource = {
  sourceName: "admin-status-pill-class-helper.js",
  body: renderAdminStatusPillClassBrowserHelper(),
};
