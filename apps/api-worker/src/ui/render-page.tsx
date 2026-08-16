import type { Context, Hono } from "hono";
import { jsxRenderer } from "hono/jsx-renderer";
import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import type { AppEnv } from "../app";
import { PageAssets, type PageAssetKey } from "./page-assets";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;
type PageVariant = "shell" | "open" | "admin";

interface PageRenderProps {
  title: string;
  head?: HonoElement | readonly HonoElement[];
  variant?: PageVariant;
}

const PageLayout = ({
  title,
  head,
  variant = "shell",
  children,
}: PropsWithChildren<PageRenderProps>): HonoElement => {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{title}</title>
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="icon" href="/favicon.ico" sizes="any" />
        {head}
      </head>
      <body data-variant={variant}>
        <main>{children}</main>
      </body>
    </html>
  );
};

declare module "hono" {
  interface ContextRenderer {
    (content: HonoElement, props: PageRenderProps): Response | Promise<Response>;
  }
}

type PageHeadContent = HonoElement | readonly HonoElement[] | undefined;

export interface AppPage {
  title: string;
  body: HonoElement;
  head?: HonoElement | readonly HonoElement[];
  variant?: PageVariant;
}

const shellHead = (head: PageHeadContent): HonoElement => {
  return (
    <>
      <PageAssets keys={["foundationCss"]} />
      {head ?? null}
    </>
  );
};

export const appPage = (input: {
  title: string;
  body: HonoElement;
  head?: PageHeadContent;
  assets?: readonly PageAssetKey[];
  variant?: PageVariant;
}): AppPage => {
  const assets = input.assets ?? [];
  const head = (
    <>
      {assets.length === 0 ? null : <PageAssets keys={assets} />}
      {input.head ?? null}
    </>
  );

  return {
    title: input.title,
    body: input.body,
    head,
    ...(input.variant === undefined ? {} : { variant: input.variant }),
  };
};

export const renderAppPage = (
  c: Context<AppEnv>,
  page: AppPage,
  status?: 200 | 400 | 403 | 404 | 500,
): Response | Promise<Response> => {
  if (status !== undefined) {
    c.status(status);
  }

  return c.render(page.body, {
    title: page.title,
    ...(page.head === undefined ? {} : { head: page.head }),
    ...(page.variant === undefined ? {} : { variant: page.variant }),
  });
};

export const renderAppPageToString = (page: AppPage): string => {
  const document = (
    <PageLayout
      title={page.title}
      head={shellHead(page.head)}
      {...(page.variant === undefined ? {} : { variant: page.variant })}
    >
      {page.body}
    </PageLayout>
  );

  const renderable = document as { toString(): string };
  return renderable.toString();
};

export const registerAppPageRenderer = (app: Hono<AppEnv>): void => {
  app.use(
    "*",
    jsxRenderer<AppEnv>(({ children, ...props }: PropsWithChildren<PageRenderProps>) => {
      return (
        <PageLayout
          title={props.title}
          head={shellHead(props.head)}
          {...(props.variant === undefined ? {} : { variant: props.variant })}
        >
          {children}
        </PageLayout>
      );
    }),
  );
};
