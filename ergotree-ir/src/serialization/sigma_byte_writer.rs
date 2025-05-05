//! Sigma byte stream writer
use super::constant_store::ConstantStore;
use core2::io::Write;
use sigma_ser::vlq_encode::WriteSigmaVlqExt;

/// Implementation for SigmaByteWrite
pub struct SigmaByteWriter<'a, W> {
    inner: &'a mut W,
    /// Constant store where constants (swapped for placeholders) are stored
    pub constant_store: Option<ConstantStore>,
    keystone_serialization: bool,
}

impl<'a, W: Write> SigmaByteWriter<'a, W> {
    /// Make a new writer with underlying Write and optional constant store
    pub fn new(w: &'a mut W, constant_store: Option<ConstantStore>) -> SigmaByteWriter<'a, W> {
        SigmaByteWriter {
            inner: w,
            constant_store,
            keystone_serialization: false,
        }
    }

    /// Make a new writer using keystone serialization schema
    pub fn new_with_keystone_serialization(
        w: &'a mut W,
        constant_store: Option<ConstantStore>,
    ) -> SigmaByteWriter<'a, W> {
        SigmaByteWriter {
            inner: w,
            constant_store,
            keystone_serialization: true,
        }
    }
}

/// Sigma byte writer trait with a store for constant segregation
pub trait SigmaByteWrite: WriteSigmaVlqExt {
    /// Constant store (if any) attached to the writer to collect segregated constants
    fn constant_store_mut_ref(&mut self) -> Option<&mut ConstantStore>;
    /// Option to enable keystone serialization schema
    fn keystone_serialization(&self) -> bool;
}

impl<'a, W: Write> Write for SigmaByteWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> core2::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> core2::io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, W: Write> SigmaByteWrite for SigmaByteWriter<'a, W> {
    fn constant_store_mut_ref(&mut self) -> Option<&mut ConstantStore> {
        self.constant_store.as_mut()
    }

    fn keystone_serialization(&self) -> bool {
        self.keystone_serialization
    }
}
