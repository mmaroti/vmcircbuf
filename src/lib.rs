// Copyright (C) 2020 Miklos Maroti
// Licensed under the MIT license (see LICENSE)

use std::io::{Error, ErrorKind};
use std::ops::{Index, IndexMut};
use std::slice::SliceIndex;
use std::sync::atomic::{AtomicI32, Ordering};
use std::{cmp, process, ptr, slice};

/// A unique identifier used to create shared memory mapped files.
static BUFFER_ID: AtomicI32 = AtomicI32::new(0);

/// A raw circular buffer of bytes. The buffer holds exactly `size` many
/// bytes but it is presented as a `size + wrap` length slice where the last
/// `wrap` many bytes overlap with the first `wrap` many bytes of the slice.
/// This magic trick is performed with virtual memory, the same physical pages
/// are mapped both at the start and at the end of the buffer.
///
/// # Examples
/// ```
/// let mut buffer = vmcircbuf::Buffer::new(0, 0).unwrap();
/// let size = buffer.size();
/// let wrap = buffer.wrap();
/// let slice: &mut [u8] = buffer.as_mut_slice();
/// assert_eq!(slice.len(), size + wrap);
///
/// for a in slice.iter_mut() {
///     *a = 0;
/// }
/// slice[0] = 123;
/// assert_eq!(slice[size], 123);
/// ```
pub struct Buffer {
    ptr: *const u8,
    len: usize,
    size: usize,
    #[cfg(windows)]
    handle: *const std::ffi::c_void,
}

fn os_error(message: &'static str) -> Error {
    let kind = Error::last_os_error().kind();
    Error::new(kind, message)
}

#[cfg(unix)]
unsafe fn vm_granularity() -> Result<usize, Error> {
    extern crate libc;

    let granularity = libc::sysconf(libc::_SC_PAGESIZE);
    if granularity <= 0 {
        Err(os_error("sysconf failed"))
    } else {
        Ok(granularity as usize)
    }
}

#[cfg(unix)]
unsafe fn vm_create(name: &str, size: usize, wrap: usize) -> Result<Buffer, Error> {
    extern crate libc;
    use std::ffi::CString;

    // convert name to c-string
    let name = CString::new(name)?;
    let mut err: Option<Error> = None;

    // create temporary shared memory file
    let file_desc = libc::shm_open(
        name.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    );
    if file_desc < 0 {
        err = Some(os_error("shm_open failed"));
    }

    // truncate the file to size + wrap
    if err.is_none() {
        let ret = libc::ftruncate(file_desc, (size + wrap) as libc::off_t);
        if ret != 0 {
            err = Some(os_error("ftruncate failed"));
        }
    }

    // map it fully
    let mut first_copy = libc::MAP_FAILED;
    if err.is_none() {
        first_copy = libc::mmap(
            ptr::null_mut(),
            size + wrap,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file_desc,
            0,
        );
        if first_copy == libc::MAP_FAILED {
            err = Some(os_error("first mmap failed"));
        }
    }

    // unmap the wrap part
    if err.is_none() {
        let ret = libc::munmap(first_copy.add(size), wrap);
        if ret != 0 {
            err = Some(os_error("munmap failed"));
        }
    }

    // memory map the wrap part again
    if err.is_none() {
        let second_copy = libc::mmap(
            first_copy.add(size),
            wrap,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file_desc,
            0,
        );
        if second_copy == libc::MAP_FAILED {
            err = Some(os_error("second mmap failed"));
        } else if second_copy != first_copy.add(size) {
            err = Some(Error::new(ErrorKind::Other, "bad second address"));
        }
    }

    // unmap memory if error
    if err.is_some() && first_copy != libc::MAP_FAILED {
        libc::munmap(first_copy, size + wrap);
    }

    if file_desc >= 0 {
        // close the file descriptor
        let ret = libc::close(file_desc);
        if ret != 0 && err.is_none() {
            err = Some(os_error("close failed"));
        }

        // unlink the shared memory
        let ret = libc::shm_unlink(name.as_ptr());
        if ret != 0 && err.is_none() {
            err = Some(os_error("shm_unlink failed"));
        }
    }

    match err {
        Some(err) => Err(err),
        None => Ok(Buffer {
            ptr: first_copy as *const u8,
            len: size + wrap,
            size,
        }),
    }
}

#[cfg(unix)]
impl Drop for Buffer {
    fn drop(&mut self) {
        extern crate libc;

        let ptr = self.ptr as *mut libc::c_void;
        let ret = unsafe { libc::munmap(ptr, self.len) };
        debug_assert_eq!(ret, 0);
    }
}

#[cfg(windows)]
unsafe fn vm_granularity() -> Result<usize, Error> {
    extern crate winapi;
    use std::mem;
    use winapi::um::sysinfoapi::GetSystemInfo;

    let mut info = mem::zeroed();
    GetSystemInfo(&mut info);
    let granularity = info.dwAllocationGranularity as usize;
    if granularity <= 0 {
        Err(Error::new(ErrorKind::Other, "invalid granularity"))
    } else {
        Ok(granularity)
    }
}

#[cfg(windows)]
unsafe fn vm_create(name: &str, size: usize, wrap: usize) -> Result<Buffer, Error> {
    extern crate winapi;
    use std::ffi::OsStr;
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use winapi::shared::basetsd::SIZE_T;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::memoryapi::{
        CreateFileMappingW, MapViewOfFileEx, UnmapViewOfFile, VirtualAlloc, VirtualFree,
        FILE_MAP_WRITE,
    };
    use winapi::um::winnt::{MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE};

    // encode name as WSTR
    let name: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let mut err: Option<Error> = None;

    // create a paging file
    debug_assert!(size <= u32::max_value as usize);
    let handle = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        ptr::null_mut(),
        PAGE_READWRITE,
        0 as DWORD,
        size as DWORD,
        name.as_ptr(),
    );
    if handle == ptr::null_mut() || handle == INVALID_HANDLE_VALUE {
        err = Some(os_error("CreateFileMappingW failed"));
    }

    // allocate virtual memory
    let mut first_copy = ptr::null_mut();
    if err.is_none() {
        first_copy = VirtualAlloc(
            ptr::null_mut(),
            (size + wrap) as SIZE_T,
            MEM_RESERVE,
            PAGE_NOACCESS,
        );
        if first_copy == ptr::null_mut() {
            err = Some(os_error("VirtualAlloc failed"));
        }
    }

    // and free it, we need the address only
    if err.is_none() {
        let ret = VirtualFree(first_copy, 0 as SIZE_T, MEM_RELEASE);
        if ret == 0 {
            err = Some(os_error("VirtualFree failed"));
        }
    }

    // map first copy
    if err.is_none() {
        let first_temp = MapViewOfFileEx(
            handle,
            FILE_MAP_WRITE,
            0 as DWORD,
            0 as DWORD,
            size as SIZE_T,
            first_copy,
        );
        if first_temp == ptr::null_mut() {
            err = Some(os_error("first MapViewOfFileEx failed"));
        } else if first_temp != first_copy {
            err = Some(os_error("invalid first address"));
        }
    }

    // map second copy
    if err.is_none() {
        let second_copy = MapViewOfFileEx(
            handle,
            FILE_MAP_WRITE,
            0 as DWORD,
            0 as DWORD,
            wrap as SIZE_T,
            first_copy.add(size),
        );
        if second_copy == ptr::null_mut() {
            err = Some(os_error("second MapViewOfFileEx failed"));
        } else if second_copy != first_copy.add(size) {
            err = Some(os_error("invalid second address"));
        }
    }

    // unmap memory on error
    if err.is_some() && first_copy != ptr::null_mut() {
        UnmapViewOfFile(first_copy);
        UnmapViewOfFile(first_copy.add(size));
    }

    if err.is_some() {
        CloseHandle(handle);
    }

    match err {
        Some(err) => Err(err),
        None => Ok(Buffer {
            ptr: first_copy as *const u8,
            len: size + wrap,
            size,
            handle: handle as *const std::ffi::c_void,
        }),
    }
}

#[cfg(windows)]
impl Drop for Buffer {
    fn drop(&mut self) {
        extern crate winapi;
        use winapi::ctypes::c_void;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::memoryapi::UnmapViewOfFile;

        let ptr = self.ptr as *mut c_void;
        let ret = unsafe { UnmapViewOfFile(ptr) };
        debug_assert_ne!(ret, 0);
        let ret = unsafe { UnmapViewOfFile(ptr.add(self.size)) };
        debug_assert_ne!(ret, 0);

        let handle = self.handle as *mut c_void;
        let ret = unsafe { CloseHandle(handle) };
        debug_assert_ne!(ret, 0);
    }
}

impl Buffer {
    /// Returns the virtual memory mapping granularity of the underlying
    /// operating system. On Unix this is the page size, which is typically
    /// 4096 bytes. On Windows this is the allocation granularity, which is
    /// typically 65536 bytes.
    #[inline]
    pub fn granularity() -> Result<usize, Error> {
        unsafe { vm_granularity() }
    }

    /// Creates a new circular buffer with the given `size` and `wrap`. The
    /// returned `size` and `wrap` will be rounded up to an integer multiple
    /// of the granularity. The `wrap` value cannot be larger than `size`, and
    /// both can be zero to get exactly the granularity size.
    pub fn new(mut size: usize, mut wrap: usize) -> Result<Buffer, Error> {
        let granularity = Buffer::granularity()?;

        // round up to a multiple of the granularity size, be safe
        size = cmp::max(size, granularity);
        size = ((size + granularity - 1) / granularity) * granularity;
        wrap = cmp::max(wrap, granularity);
        wrap = ((wrap + granularity - 1) / granularity) * granularity;
        if wrap > size || size + wrap > i32::max_value() as usize {
            return Err(Error::new(ErrorKind::Other, "invalid sizes"));
        }

        // create temporary file name
        let name = format!(
            "/rust-vmcircbuf-{}-{}",
            process::id(),
            BUFFER_ID.fetch_add(1, Ordering::Relaxed)
        );

        unsafe { vm_create(&name, size, wrap) }
    }

    /// Returns the size of the circular buffer.
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the wrap of the circular buffer.
    #[inline]
    pub fn wrap(&self) -> usize {
        self.len - self.size
    }

    /// Returns an immutable slice of the circular buffer. The last `wrap`
    /// many bytes are mapped to the first `wrap` many bytes, so you can
    /// read the same content at both places.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Returns a mutable slice of the circular buffer. The last `wrap`
    /// many bytes are mapped to the first `wrap` many bytes, so you can
    /// read and write the same content at both places.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) }
    }
}

unsafe impl Send for Buffer {}
unsafe impl Sync for Buffer {}

impl<I: SliceIndex<[u8]>> Index<I> for Buffer {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        self.as_slice().index(index)
    }
}

impl<I: SliceIndex<[u8]>> IndexMut<I> for Buffer {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        self.as_mut_slice().index_mut(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap() {
        let granularity = Buffer::granularity().unwrap();
        println!("granularity: {}", granularity);
        let mut buffer = Buffer::new(2 * granularity, granularity).unwrap();
        let size = buffer.size();
        let wrap = buffer.wrap();
        println!("buffer size: {}, wrap: {}", size, wrap);

        for (i, a) in buffer.as_mut_slice().iter_mut().enumerate() {
            let b = i % 101;
            *a = b as u8;
        }

        for (i, a) in buffer.as_slice().iter().take(wrap).enumerate() {
            let b = (i + size) % 101;
            assert_eq!(*a, b as u8);
        }

        let slice = buffer.as_mut_slice();
        assert_eq!(slice.len(), size + wrap);

        for a in slice.iter_mut() {
            *a = 0;
        }

        slice[0] = 123;
        assert_eq!(slice[size], 123);
    }
}
