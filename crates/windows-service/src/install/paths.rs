use super::*;
use std::{
    ffi::OsString,
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
};
use windows_sys::Win32::{
    System::Com::CoTaskMemFree,
    UI::Shell::{FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
};

pub(super) fn require_install_directory(directory: &Path) -> io::Result<()> {
    let mut pointer = ptr::null_mut();
    let code = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramFiles,
            KF_FLAG_DEFAULT as u32,
            ptr::null_mut(),
            &mut pointer,
        )
    };
    if code < 0 {
        return Err(io::Error::from_raw_os_error(code));
    }
    struct Allocation(*mut u16);
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe {
                CoTaskMemFree(self.0.cast());
            }
        }
    }
    let _allocation = Allocation(pointer);
    if pointer.is_null() {
        return Err(invalid());
    }
    let mut length = 0;
    while length < 32767 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    if length == 32767 {
        return Err(invalid());
    }
    let root =
        PathBuf::from(unsafe { OsString::from_wide(std::slice::from_raw_parts(pointer, length)) });
    let expected = root.join("SirinVPN");
    let given = directory.to_str().ok_or_else(invalid)?;
    if !directory.is_absolute()
        || !given.eq_ignore_ascii_case(expected.to_str().ok_or_else(invalid)?)
    {
        return Err(invalid());
    }
    Ok(())
}
