export type ThemePreference = "system" | "light" | "dark";

export type AppPreferences = {
  start_on_login: boolean;
  launch_minimized: boolean;
  close_to_tray: boolean;
  notifications: boolean;
  animations: boolean;
  theme: ThemePreference;
  /** "system" (follow the OS language list) or a language tag; absent from older shells. */
  language?: string;
};

export type NotificationPermission =
  "granted" | "denied" | "prompt" | "prompt-with-rationale";

export type PreferencesSnapshot = {
  font_scale?: number;
  preferences: AppPreferences;
  startup_available: boolean;
  tray_available: boolean;
  notification_permission: NotificationPermission;
};
