import { isAndroid } from "../platform";
import { documentDir, homeDir, join } from "@tauri-apps/api/path";

export async function preferredBackupDirectory(): Promise<string | undefined> {
  if (isAndroid) return undefined;
  for (const resolveDirectory of [documentDir, homeDir]) {
    try {
      const directory = await resolveDirectory();
      if (directory) return directory;
    } catch {
      // Some desktop environments do not define an XDG documents directory.
    }
  }
  return undefined;
}

export async function preferredBackupPath(filename: string): Promise<string> {
  const directory = await preferredBackupDirectory();
  return directory ? join(directory, filename) : filename;
}
