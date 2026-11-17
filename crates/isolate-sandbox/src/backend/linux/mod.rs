//! Linux-specific sandbox backends.
//! All modules in this file are only compiled on Linux.

#[cfg(target_os = "linux")]
pub mod ebpf;
#[cfg(target_os = "linux")]
pub mod seccomp;
#[cfg(target_os = "linux")]
pub mod landlock;
#[cfg(target_os = "linux")]
pub mod namespace;
#[cfg(target_os = "linux")]
pub mod container;
#[cfg(target_os = "linux")]
pub mod kvm;
