//! Fake blob store: bytes by CID, behind an anonymous token. It recomputes
//! the CID on put, as the spec's store protocol says. Replaced by the blob
//! store service and `hum-store` (W1 storage).

use std::collections::HashMap;

use crate::ports::{BlobStore, Cid, Refusal, TapeRef, blob_cid};

/// The fake store.
pub struct FakeBlobStore {
    tape: TapeRef,
    blobs: HashMap<Cid, Vec<u8>>,
}

impl FakeBlobStore {
    /// New.
    pub fn new(tape: TapeRef) -> Self {
        Self {
            tape,
            blobs: HashMap::new(),
        }
    }

    /// Blobs held.
    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }
}

impl BlobStore for FakeBlobStore {
    fn put(&mut self, token: &str, cid: &Cid, bytes: &[u8]) -> Result<(), Refusal> {
        // The store sees the token, the CID and the bytes (ciphertext for sealed blobs).
        self.tape
            .borrow_mut()
            .see_bytes("store", "put", &(token, cid, bytes.len()), bytes);
        if !token.starts_with("pp_") {
            return Err(Refusal("store requires an anonymous token".into()));
        }
        if blob_cid(bytes) != *cid {
            return Err(Refusal("CID mismatch".into()));
        }
        self.blobs.insert(cid.clone(), bytes.to_vec());
        Ok(())
    }

    fn get(&mut self, token: &str, cid: &Cid) -> Result<Vec<u8>, Refusal> {
        self.tape.borrow_mut().see("store", "get", &(token, cid));
        self.blobs
            .get(cid)
            .cloned()
            .ok_or_else(|| Refusal("no such blob".into()))
    }
}
