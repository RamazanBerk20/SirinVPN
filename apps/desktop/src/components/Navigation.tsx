import { House, Database, Devices, GearSix } from "@phosphor-icons/react";

export type Page = "home" | "servers" | "devices" | "settings";
const pages = [
  { id: "home", label: "Home", hint: "Connect & manage", icon: House },
  {
    id: "servers",
    label: "Servers",
    hint: "Your infrastructure",
    icon: Database,
  },
  { id: "devices", label: "Devices", hint: "Manage access", icon: Devices },
  {
    id: "settings",
    label: "Settings",
    hint: "Preferences & maintenance",
    icon: GearSix,
  },
] as const;

export function Navigation({
  page,
  onChange,
  mobile = false,
}: {
  page: Page;
  onChange: (page: Page) => void;
  mobile?: boolean;
}) {
  return (
    <nav
      className={mobile ? "bottom-navigation" : "primary-navigation"}
      aria-label={mobile ? "Mobile navigation" : "Main navigation"}
    >
      {pages.map(({ id, label, icon: Icon }) => (
        <button
          key={id}
          type="button"
          aria-current={page === id ? "page" : undefined}
          onClick={() => onChange(id)}
        >
          <Icon size={25} weight={page === id ? "duotone" : "regular"} />
          <span>
            <strong>{label}</strong>
          </span>
        </button>
      ))}
    </nav>
  );
}
