vmcircbuf
=========
[![Build Status](https://travis-ci.org/mmaroti/vmcircbuf.svg?branch=master)](https://travis-ci.org/mmaroti/vmcircbuf)
[![Crate](https://img.shields.io/crates/v/vmcircbuf)](https://crates.io/crates/vmcircbuf)
[![GitHub](https://img.shields.io/github/license/mmaroti/vmcircbuf)](LICENSE)

This is a simple crate to create a circular buffer that magically wraps around
without any copying. The buffer holds exactly `size` many bytes but it is 
presented as a `size + wrap` length slice where the last `wrap` many bytes
overlap with the first `wrap` many bytes of the slice. This magic trick is
performed with virtual memory, the same physical pages are mapped both at the
start and at the end of the buffer. This crate is working on Linux, OSX, 
Windows, iOS, Android, Raspberry PI and MIPS.

```
let mut buffer = Buffer::new(0, 0).unwrap();
let size = buffer.size();
let wrap = buffer.size();
let slice: &mut [u8] = buffer.as_mut_slice();
assert_eq!(slice.len(), size + wrap);

for a in slice.iter_mut() {
    *a = 0;
}

slice[0] = 123;
assert_eq!(slice[size], 123);
```
