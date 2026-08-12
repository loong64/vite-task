//! Anonymous memory mappings.
//!
//! Re-exposed from rustix as-is: these are single syscalls against the
//! kernel's own address-space bookkeeping — no libc state, no locks, no
//! allocation — so they already meet this crate's rules everywhere it
//! promises to work. What this module adds is the curation (being listed
//! here is what marks them safe for signal handlers, fork children, and
//! pre-libc startup) and the crate-level backend check, which guarantees
//! they cannot silently turn into libc calls on Linux.

#[cfg(not(all(target_os = "linux", target_arch = "loongarch64")))]
pub use rustix::mm::{MapFlags, MprotectFlags, ProtFlags, mmap_anonymous, mprotect, munmap};

#[cfg(all(target_os = "linux", target_arch = "loongarch64"))]
mod linux {
    use core::ffi::c_void;

    pub use rustix::mm::{MapFlags, MprotectFlags, ProtFlags};

    use crate::{Errno, Result};

    /// `MAP_ANONYMOUS`, defined by the Linux UAPI on every architecture supported
    /// by this crate.
    const MAP_ANONYMOUS: u32 = 0x20;

    /// Maps anonymous memory using Linux's `mmap` syscall.
    ///
    /// # Safety
    ///
    /// The same safety requirements as [`rustix::mm::mmap_anonymous`] apply.
    #[inline]
    pub unsafe fn mmap_anonymous(
        addr: *mut c_void,
        length: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> Result<*mut c_void> {
        // SAFETY: upheld by this function's caller. `-1` is the Linux `MAP_FAILED`
        // file-descriptor argument for an anonymous mapping.
        let mapped = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::mmap,
                addr.addr(),
                length,
                prot.bits() as usize,
                flags.bits() as usize | MAP_ANONYMOUS as usize,
                usize::MAX,
                0,
            )
        }
        .map_err(|errno| Errno::from_raw_os_error(errno.into_raw()))?;

        Ok(mapped as *mut c_void)
    }

    /// Changes protection on an existing mapping using Linux's `mprotect` syscall.
    ///
    /// # Safety
    ///
    /// The same safety requirements as [`rustix::mm::mprotect`] apply.
    #[inline]
    pub unsafe fn mprotect(ptr: *mut c_void, length: usize, flags: MprotectFlags) -> Result<()> {
        // SAFETY: upheld by this function's caller.
        unsafe {
            syscalls::syscall3(syscalls::Sysno::mprotect, ptr.addr(), length, flags.bits() as usize)
        }
        .map_err(|errno| Errno::from_raw_os_error(errno.into_raw()))?;
        Ok(())
    }

    /// Unmaps memory using Linux's `munmap` syscall.
    ///
    /// # Safety
    ///
    /// The same safety requirements as [`rustix::mm::munmap`] apply.
    #[inline]
    pub unsafe fn munmap(addr: *mut c_void, length: usize) -> Result<()> {
        // SAFETY: upheld by this function's caller.
        unsafe { syscalls::syscall2(syscalls::Sysno::munmap, addr.addr(), length) }
            .map_err(|errno| Errno::from_raw_os_error(errno.into_raw()))?;
        Ok(())
    }
}

#[cfg(all(target_os = "linux", target_arch = "loongarch64"))]
pub use linux::{MapFlags, MprotectFlags, ProtFlags, mmap_anonymous, mprotect, munmap};
