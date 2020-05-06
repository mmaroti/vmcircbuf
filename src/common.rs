// Copyright (C) 2020 Miklos Maroti
// Licensed under the MIT license (see LICENSE)

/// Represents the producer side of a circular buffer.
pub trait Producer {
    /// Returns the wrap of the underlying buffer.
    fn wrap(&self) -> usize;

    /// Obtains a mutable reference to a continuous slice where new data
    /// can be written. This method is guaranteed to return a slice with
    /// a length that is at least `len` bytes long. If there is not enough
    /// space available, then this method blocks. You can always pass `0` to
    /// get access to as much space as possible without blocking. Once you are
    /// done mutating the buffer, you must call `produce` with the number of
    /// bytes you have written, which can be less than `len`, to update the
    /// write pointer.
    /// # Safety
    /// This method panics if you specify a length that is larger than `wrap`.
    fn write(&mut self, len: usize) -> &mut [u8];

    /// Updates the write pointer of the buffer with the specified amount.
    /// Calling this method with `0` is possible, but has no effect.
    /// # Safety
    /// This method panics if you are attempting to produce more data than
    /// currently available as indicated by the length of the slice returned
    /// by `access`.
    fn produce(&mut self, len: usize);
}

/// Represents the consumer side of a circular buffer.
pub trait Consumer {
    /// Returns the wrap of the underlying buffer.
    fn wrap(&self) -> usize;

    /// Obtains a reference to a continuous slice where new data can be read
    /// from. The returned slice is mutable, so you can use it as a temporary
    /// working area if needed. This method is guaranteed to return a slice
    /// with a length that is at least `len` bytes long. If there is not enough
    /// space available, then this method blocks. You can always pass `0` to
    /// get access to as much data as possible without blocking. Once you are
    /// done reading the buffer, you must call `consume` with the number of
    /// bytes you have read, which can be less than `len`, to update the
    /// read pointer.
    /// # Safety
    /// This method panics if you specify a length that is larger than `wrap`.
    fn read(&mut self, len: usize) -> &mut [u8];

    /// Updates the read pointer of the buffer with the specified amount.
    /// Calling this method with `0` is possible, but has no effect.
    /// # Safety
    /// This method panics if you are attempting to consume more data than
    /// currently available as indicated by the length of the slice returned
    /// by `access`.
    fn consume(&mut self, len: usize);
}
