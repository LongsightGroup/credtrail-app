import type { HtmlEscapedString } from "hono/utils/html";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export const AdminLinkedImageWithFallback = (input: {
  href: string;
  linkClassName: string;
  imageClassName: string;
  placeholderClassName: string;
  ariaLabel: string;
  alt: string;
  placeholderText: string;
}): HonoElement => {
  return (
    <span class="ct-admin__image-fallback-frame" data-admin-image-fallback="ready">
      <a
        class={input.linkClassName}
        href={input.href}
        target="_blank"
        rel="noopener noreferrer"
        aria-label={input.ariaLabel}
        data-admin-image-link=""
      >
        <img
          class={input.imageClassName}
          src={input.href}
          alt={input.alt}
          loading="lazy"
          data-admin-image=""
        />
      </a>
      <span class={input.placeholderClassName} data-admin-image-placeholder="" hidden>
        {input.placeholderText}
      </span>
    </span>
  );
};
