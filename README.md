vmcircbuf
=========
[![Build Status](https://travis-ci.org/mmaroti/vmcircbuf.svg?branch=master)](https://travis-ci.org/mmaroti/vmcircbuf)

This is a simple crate to create a circular buffer that magically wraps around
by mapping the same physical memory page twice into the virtual address space.
