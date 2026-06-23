import { AdminActions, AdminButtonLink, AdminPageHeader, AdminPanel } from "../admin/components";
import { appPage, type AppPage } from "../ui/render-page";

export const adminRoleRequiredPage = (tenantId: string): AppPage => {
  return appPage({
    title: "Admin access required",
    assets: ["institutionAdminCss"],
    variant: "admin",
    body: (
      <section class="ct-admin-content">
        <AdminPageHeader
          as="header"
          title="Admin role required"
          description={
            <>
              Your current organization membership role does not allow institution admin access for{" "}
              <strong>{tenantId}</strong>.
            </>
          }
        />
        <section class="ct-admin ct-stack">
          <AdminPanel>
            <p class="ct-admin__eyebrow">Institution Admin</p>
            <p>
              Ask an existing tenant admin/owner to grant your account an admin role, then retry.
            </p>
            <AdminActions>
              <AdminButtonLink
                href={`/showcase/${encodeURIComponent(tenantId)}`}
                variant="secondary"
              >
                View public badge showcase
              </AdminButtonLink>
            </AdminActions>
          </AdminPanel>
        </section>
      </section>
    ),
  });
};

export const reportingAccessRequiredPage = (tenantId: string): AppPage => {
  return appPage({
    title: "Reporting access required",
    assets: ["institutionAdminCss"],
    variant: "admin",
    body: (
      <section class="ct-admin-content">
        <AdminPageHeader
          as="header"
          title="Reporting access required"
          description={
            <>
              Your current organization membership does not allow reporting access for{" "}
              <strong>{tenantId}</strong>.
            </>
          }
        />
        <section class="ct-admin ct-stack">
          <AdminPanel>
            <p class="ct-admin__eyebrow">Reporting</p>
            <p>
              Ask a tenant admin to grant reporting scope or a broader reporting role, then retry.
            </p>
          </AdminPanel>
        </section>
      </section>
    ),
  });
};
