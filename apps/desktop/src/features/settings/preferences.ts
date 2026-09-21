export type AppPreferences = {
  start_on_login: boolean;
  launch_minimized: boolean;
  close_to_tray: boolean;
  notifications: boolean;
  animations: boolean;
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
