vmcircbuf
=========
[![Build Status](https://travis-ci.org/mmaroti/vmcircbuf.svg?branch=master)](https://travis-ci.org/mmaroti/vmcircbuf)
[![Crate](https://img.shields.io/crates/v/vmcircbuf)](https://crates.io/crates/vmcircbuf)
[![GitHub](https://img.shields.io/github/license/mmaroti/vmcircbuf)](LICENSE)

This is a simple crate to create a circular buffer that magically wraps around
without any copying. This is achieved by mapping the same physical memory pages 
twice into the virtual address space. This crate is working on Linux, OSX, 
Windows, Android, Raspberry PI, MIPS.

```
let mut buffer = Buffer::new(0, 0).unwrap();
let size = buffer.size();

for (i, a) in buffer.slice_mut(0, size).iter_mut().enumerate() {
    *a = i as u8;
}
for (i, a) in buffer.slice(10, size).iter().enumerate() {
    assert_eq!(*a, (i + 10) as u8);
}
```
