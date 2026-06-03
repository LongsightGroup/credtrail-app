import type { HtmlEscapedString } from "hono/utils/html";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export type AdminSidebarNavIconName =
  | "home"
  | "issuance"
  | "learnerRecords"
  | "badgeProgram"
  | "reporting"
  | "peopleAccess";

export interface AdminSidebarLinkItem {
  href: string;
  label: string;
  icon?: AdminSidebarNavIconName;
  isCurrent?: boolean;
}

export interface AdminSidebarGroupItem {
  label: string;
  icon: AdminSidebarNavIconName;
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

const AdminSidebarNavIcon = (input: { name: AdminSidebarNavIconName }): HonoElement => {
  const iconProps = {
    class: "ct-admin-sidebar__nav-icon",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    "stroke-width": "1.75",
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
    "aria-hidden": "true",
    focusable: "false",
  };

  switch (input.name) {
    case "home":
      return (
        <svg {...iconProps}>
          <path d="m3 10 9-7 9 7"></path>
          <path d="M5 10v10a1 1 0 0 0 1 1h4v-6h4v6h4a1 1 0 0 0 1-1V10"></path>
        </svg>
      );
    case "issuance":
      return (
        <svg {...iconProps}>
          <path d="m22 2-7 20-4-9-9-4Z"></path>
          <path d="M22 2 11 13"></path>
        </svg>
      );
    case "learnerRecords":
      return (
        <svg {...iconProps}>
          <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"></path>
          <circle cx="9" cy="7" r="4"></circle>
          <path d="M22 21v-2a4 4 0 0 0-3-3.87"></path>
          <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
        </svg>
      );
    case "badgeProgram":
      return (
        <svg {...iconProps}>
          <circle cx="12" cy="8" r="5"></circle>
          <path d="M8.5 13.5 7 21l5-2.5L17 21l-1.5-7.5"></path>
        </svg>
      );
    case "reporting":
      return (
        <svg {...iconProps}>
          <line x1="18" y1="20" x2="18" y2="10"></line>
          <line x1="12" y1="20" x2="12" y2="4"></line>
          <line x1="6" y1="20" x2="6" y2="14"></line>
        </svg>
      );
    case "peopleAccess":
      return (
        <svg {...iconProps}>
          <path d="M16 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
          <circle cx="10" cy="8" r="3"></circle>
          <path d="M20 8v6"></path>
          <path d="M23 11h-6"></path>
        </svg>
      );
  }
};

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
      {link.icon === undefined || options?.nested === true ? null : (
        <AdminSidebarNavIcon name={link.icon} />
      )}
      <span class="ct-admin-sidebar__link-label">{link.label}</span>
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
            <AdminSidebarNavIcon name={group.icon} />
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
