import type { HtmlEscapedString } from "hono/utils/html";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export interface AdminSidebarLinkItem {
  href: string;
  label: string;
  isCurrent?: boolean;
}

export type AdminSidebarSectionIcon =
  | "analytics"
  | "configuration"
  | "credential"
  | "management"
  | "operations";

export interface AdminSidebarGroupItem {
  label: string;
  icon?: AdminSidebarSectionIcon;
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
      label: string;
      icon?: AdminSidebarSectionIcon;
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

const AdminSidebarIcon = (input: { name: AdminSidebarSectionIcon }): HonoElement => {
  const iconProps = {
    class: "ct-admin-sidebar__section-icon",
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    "stroke-linecap": "round",
    "stroke-linejoin": "round",
    "aria-hidden": "true",
    focusable: "false",
  };

  switch (input.name) {
    case "analytics":
      return (
        <svg {...iconProps}>
          <line x1="18" x2="18" y1="20" y2="10"></line>
          <line x1="12" x2="12" y1="20" y2="4"></line>
          <line x1="6" x2="6" y1="20" y2="14"></line>
        </svg>
      );
    case "configuration":
      return (
        <svg {...iconProps}>
          <path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2.4a6 6 0 1 0-4-4Z"></path>
          <circle cx="16.5" cy="7.5" r="0.5" fill="currentColor" stroke="none"></circle>
        </svg>
      );
    case "credential":
      return (
        <svg {...iconProps}>
          <rect x="4" y="4" width="16" height="16" rx="2"></rect>
          <path d="M8 9h8"></path>
          <path d="M8 13h5"></path>
          <path d="M15.5 15.5 17 17l2.5-3"></path>
        </svg>
      );
    case "management":
      return (
        <svg {...iconProps}>
          <path d="m3 7 2 2 4-4"></path>
          <path d="m3 17 2 2 4-4"></path>
          <path d="M13 6h8"></path>
          <path d="M13 12h8"></path>
          <path d="M13 18h8"></path>
        </svg>
      );
    case "operations":
      return (
        <svg {...iconProps}>
          <circle cx="11" cy="11" r="8"></circle>
          <path d="m8 11 2 2 4-4"></path>
          <path d="m21 21-4.3-4.3"></path>
        </svg>
      );
  }
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
            {group.icon === undefined ? null : <AdminSidebarIcon name={group.icon} />}
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
              <div class="ct-admin-sidebar__section-header">
                <span class="ct-admin-sidebar__section-title">
                  {section.icon === undefined ? null : <AdminSidebarIcon name={section.icon} />}
                  <span class="ct-admin-sidebar__section-label">{section.label}</span>
                </span>
              </div>
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
