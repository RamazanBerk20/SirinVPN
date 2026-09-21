use std::io;
use tauri::AppHandle;

pub fn is_enabled(_app: &AppHandle) -> io::Result<bool> {
    sirinvpn_platform::windows::startup::is_enabled(&std::env::current_exe()?)
}
pub fn set_enabled(_app: &AppHandle, enabled: bool) -> io::Result<()> {
    sirinvpn_platform::windows::startup::set_enabled(&std::env::current_exe()?, enabled)
}
