//! Windows-specific sandbox backends.

#[cfg(target_os = "windows")]
pub mod etw;
#[cfg(target_os = "windows")]
pub mod hyperv;
#[cfg(target_os = "windows")]
pub mod winsandbox;
