import type { HonoElement } from "./public-badge-ui";

export const VC_DATA_MODEL_V2_CONTEXT_URL = "https://www.w3.org/ns/credentials/v2";

export const nonEmptyText = (value: string | null): string | null => {
  if (value === null) {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
};

export const resolveAbsoluteWebUrl = (input: {
  requestUrl: string;
  value: string | null;
  isWebUrl: (value: string) => boolean;
}): string | null => {
  const text = nonEmptyText(input.value);

  if (text === null) {
    return null;
  }

  try {
    const absoluteUrl = new URL(text, input.requestUrl).toString();
    return input.isWebUrl(absoluteUrl) ? absoluteUrl : null;
  } catch {
    return null;
  }
};

export const hasContextUrl = (contextValue: unknown, expectedContextUrl: string): boolean => {
  if (typeof contextValue === "string") {
    return contextValue === expectedContextUrl;
  }

  if (!Array.isArray(contextValue)) {
    return false;
  }

  return contextValue.some((entry) => typeof entry === "string" && entry === expectedContextUrl);
};

export const buildSeoHeadContent = (options: {
  title: string;
  description: string;
  canonicalUrl: string;
  ogType: "article" | "website";
  imageUrl?: string | null;
  robots?: string;
  extraHeadContent?: HonoElement | readonly HonoElement[];
}): HonoElement => {
  const imageUrl = options.imageUrl ?? null;

  return (
    <>
      <meta name="description" content={options.description} />
      <meta name="robots" content={options.robots ?? "index, follow"} />
      <link rel="canonical" href={options.canonicalUrl} />
      <meta property="og:site_name" content="CredTrail" />
      <meta property="og:type" content={options.ogType} />
      <meta property="og:title" content={options.title} />
      <meta property="og:description" content={options.description} />
      <meta property="og:url" content={options.canonicalUrl} />
      {imageUrl === null ? null : <meta property="og:image" content={imageUrl} />}
      <meta name="twitter:card" content={imageUrl === null ? "summary" : "summary_large_image"} />
      <meta name="twitter:title" content={options.title} />
      <meta name="twitter:description" content={options.description} />
      {imageUrl === null ? null : <meta name="twitter:image" content={imageUrl} />}
      {options.extraHeadContent ?? null}
    </>
  );
};
