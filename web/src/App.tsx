import { AppShell, BrandProvider, EmptyState, useLocalePreference, useThemePreference } from "@openasy/ui";
import { AuthGate, useAuth, useInstallBrand } from "@openasy/auth/react";
import colophon from "virtual:openasy-colophon";
import { GitCompare } from "lucide-react";
import { useT } from "./i18n.ts";

export const PATHS = ["changes"];

function Product() {
  const t = useT();
  const { me } = useAuth();
  return (
    <AppShell
      product="attack-surface"
      about={colophon}
      nav={[{ id: "changes", label: t("product.changes"), icon: GitCompare }]}
      activeNav="changes"
      onNavigate={() => {}}
      user={{ name: me.user.name, role: me.user.role }}
    >
      <EmptyState title={t("product.changes")} />
    </AppShell>
  );
}

export function App() {
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  const [locale] = useLocalePreference();
  return (
    <BrandProvider theme={theme} locale={locale} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy Attack Surface">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
