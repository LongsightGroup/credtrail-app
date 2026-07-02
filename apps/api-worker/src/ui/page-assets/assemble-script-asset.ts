import type { ScriptPageAssetBuildSource } from "./build-registry";
import {
  readScriptPageAssetSource,
  scriptPageAssetSourceName,
  type ScriptPageAssetSourceReader,
} from "./script-asset-fragments";

const assembleScriptFragment = (
  scriptSource: ScriptPageAssetBuildSource["sources"][number],
  readSource: ScriptPageAssetSourceReader,
): string => {
  const body = readScriptPageAssetSource(scriptSource, readSource);

  return typeof scriptSource === "string"
    ? body
    : `/* ${scriptPageAssetSourceName(scriptSource)} */\n${body}`;
};

/** Assembles ordered JavaScript fragments into one private browser script. */
export const assembleScriptAsset = (
  source: ScriptPageAssetBuildSource,
  readSource: ScriptPageAssetSourceReader,
): string => {
  const body = source.sources
    .map((scriptSource) => assembleScriptFragment(scriptSource, readSource))
    .join("\n");

  return `(() => {\n${body}\n})();`;
};
