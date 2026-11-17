//! macOS-specific sandbox backends.

#[cfg(target_os = "macos")]
pub mod esf;
#[cfg(target_os = "macos")]
pub mod seatbelt;
#[cfg(target_os = "macos")]
pub mod virt;
#[cfg(target_os = "macos")]
pub mod netex;
