use std::io::{Error, ErrorKind};
use std::sync::atomic::{AtomicI32, Ordering};
use std::{cmp, process, ptr, slice};

/// A unique identifier used to create shared memory mapped files.
static BUFFER_ID: AtomicI32 = AtomicI32::new(0);

/// A raw circular buffer of bytes. The buffer holds exactly `size` many
/// bytes, and any at most `wrap` many bytes can be accessed as a continuos
/// slice where the end wraps over to the beginning. This trick is performed
/// with virtual memory, the same physical pages are mapped both at the start
/// and after the end of the buffer.
pub struct Buffer {
    ptr: *const u8,
    size: usize,
    wrap: usize,
}

fn os_error(message: &'static str) -> Error {
    let kind = Error::last_os_error().kind();
    Error::new(kind, message)
}

#[cfg(unix)]
unsafe fn os_page_size() -> Result<usize, Error> {
    extern crate libc;

    let page = libc::sysconf(libc::_SC_PAGESIZE);
    if page <= 0 {
        Err(os_error("page_size failed"))
    } else {
        Ok(page as usize)
    }
}

#[cfg(unix)]
unsafe fn os_create(name: &str, size: usize, wrap: usize) -> Result<Buffer, Error> {
    extern crate libc;
    use std::ffi::CString;

    // convert name to c-string
    let name = CString::new(name)?;

    // create temporary shared memory file
    let file_desc = libc::shm_open(
        name.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        0o600,
    );
    if file_desc < 0 {
        return Err(os_error("shm_open failed"));
    }

    // truncate the file to size + wrap
    let ret = libc::ftruncate(file_desc, (size + wrap) as libc::off_t);
    if ret != 0 {
        let ret = os_error("first ftruncate failed");
        libc::close(file_desc);
        return Err(ret);
    }

    // map with it fully
    let first_copy = libc::mmap(
        ptr::null_mut(),
        size + wrap,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        file_desc,
        0,
    );
    if first_copy == libc::MAP_FAILED {
        let ret = os_error("first mmap failed");
        libc::close(file_desc);
        return Err(ret);
    }

    // unmap the second wrap half
    let ret = libc::munmap(first_copy.add(size), wrap);
    if ret != 0 {
        let ret = os_error("munmap failed");
        libc::close(file_desc);
        return Err(ret);
    }

    // memory map the wrap part again
    let second_copy = libc::mmap(
        first_copy.add(size),
        wrap,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        file_desc,
        0,
    );
    if second_copy == libc::MAP_FAILED {
        let ret = os_error("second mmap failed");
        libc::close(file_desc);
        return Err(ret);
    } else if second_copy != first_copy.add(size) {
        libc::close(file_desc);
        return Err(Error::new(ErrorKind::Other, "bad second address"));
    }

    // close the file descriptor
    let ret = libc::close(file_desc);
    if ret != 0 {
        return Err(os_error("close failed"));
    }

    // unlink the shared memory
    let ret = libc::shm_unlink(name.as_ptr());
    if ret != 0 {
        return Err(os_error("shm_unlink failed"));
    }

    Ok(Buffer {
        ptr: first_copy as *const u8,
        size,
        wrap,
    })
}

#[cfg(unix)]
impl Drop for Buffer {
    fn drop(&mut self) {
        extern crate libc;

        let ptr = self.ptr as *mut libc::c_void;
        let ret = unsafe { libc::munmap(ptr, 2 * self.size) };
        assert_eq!(ret, 0);
    }
}

#[cfg(windows)]
unsafe fn os_page_size() -> Result<usize, Error> {
    extern crate winapi;
    use std::mem;
    use winapi::um::sysinfoapi::GetSystemInfo;

    let mut info = mem::zeroed();
    GetSystemInfo(&mut info);
    Ok(info.dwAllocationGranularity as usize)
}

#[cfg(windows)]
unsafe fn os_create(name: &str, size: usize, wrap: usize) -> Result<Buffer, Error> {
    extern crate winapi;
    use std::ffi::OsStr;
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::memoryapi::CreateFileMappingW;
    use winapi::um::winnt::PAGE_READWRITE;

    // encode name as WSTR
    let name: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(iter::once(0))
        .collect();

    // create a paging file
    let handle = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        ptr::null_mut(),
        PAGE_READWRITE,
        0,
        size,
        name.as_ptr(),
    );
    if handle == ptr::null_mut() || handle == INVALID_HANDLE_VALUE {
        return Err(os_error("CreateFileMappingA failed"));
    }

    // close handle
    let ret = CloseHandle(handle);
    if ret == 0 {
        return Err(os_error("CloseHandle failed"));
    }

    Err(Error::new(ErrorKind::Other, "not implemented"))
}

impl Buffer {
    /// Returns the page size of the underlying operating system.
    #[inline(always)]
    pub fn page_size() -> Result<usize, Error> {
        unsafe { os_page_size() }
    }

    /// Creates a new circular buffer with the given `size` and `wrap`. The
    /// returned `size` and `wrap` will be rounded up to an integer multiple
    /// of the page size. The `wrap` value cannot be larger than `size`, and
    /// both can be zero to get the page size.
    pub fn new(mut size: usize, mut wrap: usize) -> Result<Buffer, Error> {
        let page = Buffer::page_size()?;

        // round up to a multiple of the page size, be safe
        size = cmp::max(size, page);
        size = ((size + page - 1) / page) * page;
        wrap = cmp::max(wrap, page);
        wrap = ((wrap + page - 1) / page) * page;
        if size + wrap > i32::max_value() as usize {
            return Err(Error::new(ErrorKind::Other, "invalid sizes"));
        }

        // create temporary file name
        let name = format!(
            "/rust-vmcircbuf-{}-{}",
            process::id(),
            BUFFER_ID.fetch_add(1, Ordering::Relaxed)
        );

        unsafe { os_create(&name, size, wrap) }
    }

    /// Returns the size of the circular buffer.
    #[inline(always)]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the wrap of the circular buffer.
    #[inline(always)]
    pub fn wrap(&self) -> usize {
        self.wrap
    }

    /// Returns an immutable slice of the circular buffer starting at `start`
    /// and containing `count` many elements. Note, that `start + count`
    /// cannot be larger than `size + wrap`. If `start + count` is bigger
    /// than `size`, then the returned slice will magically wrap over
    /// to the beginning of the buffer.
    #[inline(always)]
    pub fn slice(&self, start: usize, count: usize) -> &[u8] {
        assert!(start + count <= self.size + self.wrap);
        unsafe { self.slice_unchecked(start, count) }
    }

    /// This is the mutable analog of the `slice` method.
    #[inline(always)]
    pub fn slice_mut(&mut self, start: usize, count: usize) -> &mut [u8] {
        assert!(start + count <= self.size + self.wrap);
        unsafe { self.slice_mut_unchecked(start, count) }
    }

    /// This is the unsafe version of the `slice` method.
    /// # Safety
    /// Make sure that `start + count <= size + wrap` before
    /// calling this method.
    #[inline(always)]
    pub unsafe fn slice_unchecked(&self, start: usize, count: usize) -> &[u8] {
        slice::from_raw_parts(self.ptr.add(start), count)
    }

    /// This is the unsafe version of the `slice_mut` method.
    /// # Safety
    /// Make sure that `start + count <= size + wrap` before
    /// calling this method.
    #[inline(always)]
    pub unsafe fn slice_mut_unchecked(&mut self, start: usize, count: usize) -> &mut [u8] {
        slice::from_raw_parts_mut(self.ptr.add(start) as *mut u8, count)
    }
}

unsafe impl Send for Buffer {}
unsafe impl Sync for Buffer {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap() {
        let page = Buffer::page_size().unwrap();
        println!("page size: {}", page);
        let mut buffer = Buffer::new(2 * page, page).unwrap();
        let size = buffer.size();
        println!("buffer size: {}, wrap: {}", size, buffer.wrap());

        for (i, a) in buffer.slice_mut(0, size).iter_mut().enumerate() {
            *a = i as u8;
        }
        for (i, a) in buffer.slice(10, size).iter().enumerate() {
            assert_eq!(*a, ((i + 10) % size) as u8);
        }
    }
}
