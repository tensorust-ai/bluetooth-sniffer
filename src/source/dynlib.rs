//! Minimal run-time shared library loader (LoadLibraryExW / dlopen).
//!
//! Only what is needed to bind libhackrf; kept dependency-free so that the
//! crate builds with every Rust toolchain flavour (MSVC, MinGW, Linux, macOS).

use std::ffi::{CString, c_char, c_void};
use std::path::Path;

pub struct DynLib {
    handle: *mut c_void,
}

// The handle is only used to look up symbols and to unload the library.
unsafe impl Send for DynLib {}
unsafe impl Sync for DynLib {}

#[cfg(windows)]
mod sys {
    use super::*;
    use std::os::windows::ffi::OsStrExt;

    pub const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    pub fn open(path: &Path) -> Result<*mut c_void, String> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // With a directory component, resolve the library's own dependencies
        // (e.g. libusb-1.0.dll next to hackrf.dll) from that directory.
        let flags = if path.components().count() > 1 {
            LOAD_WITH_ALTERED_SEARCH_PATH
        } else {
            0
        };
        let h = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), flags) };
        if h.is_null() {
            Err(format!("LoadLibraryExW failed (error {})", unsafe {
                GetLastError()
            }))
        } else {
            Ok(h)
        }
    }

    pub fn sym(h: *mut c_void, name: &CString) -> *mut c_void {
        unsafe { GetProcAddress(h, name.as_ptr()) }
    }

    pub fn close(h: *mut c_void) {
        unsafe {
            FreeLibrary(h);
        }
    }
}

#[cfg(unix)]
mod sys {
    use super::*;
    use std::ffi::{CStr, c_int};
    use std::os::unix::ffi::OsStrExt;

    const RTLD_NOW: c_int = 2;

    #[cfg_attr(all(target_os = "linux", target_env = "gnu"), link(name = "dl"))]
    unsafe extern "C" {
        fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        fn dlclose(handle: *mut c_void) -> c_int;
        fn dlerror() -> *const c_char;
    }

    pub fn open(path: &Path) -> Result<*mut c_void, String> {
        let c = CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
        let h = unsafe { dlopen(c.as_ptr(), RTLD_NOW) };
        if h.is_null() {
            let e = unsafe { dlerror() };
            Err(if e.is_null() {
                "dlopen failed".into()
            } else {
                unsafe { CStr::from_ptr(e) }.to_string_lossy().into_owned()
            })
        } else {
            Ok(h)
        }
    }

    pub fn sym(h: *mut c_void, name: &CString) -> *mut c_void {
        unsafe { dlsym(h, name.as_ptr()) }
    }

    pub fn close(h: *mut c_void) {
        unsafe {
            dlclose(h);
        }
    }
}

impl DynLib {
    pub fn open(path: &Path) -> Result<Self, String> {
        sys::open(path).map(|handle| Self { handle })
    }

    /// Look up a function symbol.
    ///
    /// # Safety
    /// `T` must be a function pointer type matching the symbol's real
    /// signature.
    pub unsafe fn get<T: Copy>(&self, name: &str) -> Option<T> {
        assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<*mut c_void>());
        let c = CString::new(name).ok()?;
        let p = sys::sym(self.handle, &c);
        if p.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&p) })
        }
    }
}

impl Drop for DynLib {
    fn drop(&mut self) {
        sys::close(self.handle);
    }
}
