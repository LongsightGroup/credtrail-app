import type { HtmlEscapedString } from "hono/utils/html";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export interface AdminSidebarLinkItem {
  href: string;
  label: string;
  isCurrent?: boolean;
}

export interface AdminSidebarGroupItem {
  label: string;
  links: readonly AdminSidebarLinkItem[];
  defaultOpen?: boolean;
}

export type AdminSidebarSection =
  | {
      kind: "links";
      links: readonly AdminSidebarLinkItem[];
    }
  | {
      kind: "groups";
      groups: readonly AdminSidebarGroupItem[];
    };

export interface AdminSidebarFooterLink {
  href: string;
  label: string;
  isExternal?: boolean;
  target?: "_blank";
  rel?: string;
}

const AdminSidebarMenuChevron = (): HonoElement => {
  return (
    <svg
      class="ct-admin-sidebar__menu-chevron"
      viewBox="0 0 256 256"
      fill="none"
      stroke="currentColor"
      stroke-width="16"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <polyline points="96 48 176 128 96 208"></polyline>
    </svg>
  );
};

const renderSidebarLink = (
  link: AdminSidebarLinkItem,
  options?: { nested?: boolean | undefined },
): HonoElement => {
  const className =
    options?.nested === true
      ? "ct-admin-sidebar__link ct-admin-sidebar__link--nested"
      : "ct-admin-sidebar__link";

  return (
    <a
      class={className}
      href={link.href}
      aria-current={link.isCurrent === true ? "page" : undefined}
    >
      {link.label}
    </a>
  );
};

const renderSidebarLinks = (
  links: readonly AdminSidebarLinkItem[],
  options?: { nested?: boolean | undefined },
): HonoElement => {
  return (
    <ul
      class={options?.nested === true ? "ct-admin-sidebar__menu-sub" : "ct-admin-sidebar__menu"}
      role="list"
    >
      {links.map((link) => {
        return <li class="ct-admin-sidebar__menu-item">{renderSidebarLink(link, options)}</li>;
      })}
    </ul>
  );
};

const groupIsOpen = (group: AdminSidebarGroupItem): boolean => {
  return group.defaultOpen === true || group.links.some((link) => link.isCurrent === true);
};

const renderSidebarGroup = (
  group: AdminSidebarGroupItem,
  ids: { sectionIndex: number; groupIndex: number },
): HonoElement => {
  if (group.links.length === 1) {
    const link = group.links[0];
    if (link === undefined) {
      return <></>;
    }

    return (
      <li class="ct-admin-sidebar__group ct-admin-sidebar__group--flat">
        {renderSidebarLink(link)}
      </li>
    );
  }

  const isOpen = groupIsOpen(group);
  const groupContentId = `admin-sidebar-group-${ids.sectionIndex}-${ids.groupIndex}`;

  return (
    <li class="ct-admin-sidebar__group">
      <details class="ct-admin-sidebar__group-details" open={isOpen}>
        <summary class="ct-admin-sidebar__group-trigger" aria-controls={groupContentId}>
          <span class="ct-admin-sidebar__group-title">
            <span>{group.label}</span>
          </span>
          <AdminSidebarMenuChevron />
        </summary>
        <div id={groupContentId} class="ct-admin-sidebar__group-content">
          {renderSidebarLinks(group.links, { nested: true })}
        </div>
      </details>
    </li>
  );
};

export const AdminSidebar = (input: {
  brandHref: string;
  sections: readonly AdminSidebarSection[];
  footerLinks: readonly AdminSidebarFooterLink[];
}): HonoElement => {
  return (
    <aside class="ct-admin-sidebar">
      <a class="ct-admin-sidebar__brand" href={input.brandHref}>
        CredTrail
      </a>
      <nav class="ct-admin-sidebar__nav" aria-label="Admin navigation">
        {input.sections.map((section, sectionIndex) => {
          if (section.kind === "links") {
            return <div class="ct-admin-sidebar__section">{renderSidebarLinks(section.links)}</div>;
          }

          return (
            <section class="ct-admin-sidebar__section">
              <ul class="ct-admin-sidebar__groups" role="list">
                {section.groups.map((group, groupIndex) => {
                  return renderSidebarGroup(group, { sectionIndex, groupIndex });
                })}
              </ul>
            </section>
          );
        })}
      </nav>
      <div class="ct-admin-sidebar__footer">
        {input.footerLinks.map((link) => {
          const className =
            link.isExternal === true
              ? "ct-admin-sidebar__footer-link ct-admin-sidebar__link--external"
              : "ct-admin-sidebar__footer-link";

          return (
            <a class={className} href={link.href} target={link.target} rel={link.rel}>
              {link.label}
            </a>
          );
        })}
      </div>
    </aside>
  );
};
