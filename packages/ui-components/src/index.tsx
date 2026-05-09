import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export type PageVariant = "shell" | "open" | "admin";

export interface PageRenderProps {
  title: string;
  head?: HonoElement | readonly HonoElement[];
  variant?: PageVariant;
}

export const PageLayout = ({
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
