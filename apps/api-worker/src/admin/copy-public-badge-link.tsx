import { AdminButton } from "./components";
import { CtInput } from "../ui/forms";
import type { HtmlEscapedString } from "hono/utils/html";

export const CopyPublicBadgeLink = (input: {
  readonly publicBadgeUrl: string;
}): HtmlEscapedString | Promise<HtmlEscapedString> => (
  <div class="ct-stack" data-copy-public-badge>
    <AdminButton
      type="button"
      variant="secondary"
      dataAttributes={{ "data-public-badge-url": input.publicBadgeUrl }}
    >
      Copy public badge link
    </AdminButton>
    <span role="status" data-copy-status></span>
    <div hidden data-copy-fallback>
      <CtInput readonly value={input.publicBadgeUrl} ariaLabel="Public badge link" />
    </div>
  </div>
);
