export interface StylePageAssetMediaGroup {
  readonly media: string;
  readonly sourcePaths: readonly string[];
}

export type StylePageAssetSource = string | StylePageAssetMediaGroup;

export type ReadStyleSourcePath = (sourcePath: string) => string;

export const assembleStyleSource = (
  source: StylePageAssetSource,
  readSourcePath: ReadStyleSourcePath,
): string => {
  if (typeof source === "string") {
    return readSourcePath(source);
  }

  const sourceBodies = source.sourcePaths.map(readSourcePath);

  return `@media ${source.media} {\n${sourceBodies.join("\n")}\n}`;
};

export const assembleStyleAsset = (
  sources: readonly StylePageAssetSource[],
  readSourcePath: ReadStyleSourcePath,
  postProcess: (body: string) => string = (body) => body,
): string => {
  const body = sources.map((source) => assembleStyleSource(source, readSourcePath)).join("\n");

  return postProcess(body);
};
