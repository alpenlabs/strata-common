//! In-memory [`MmrNodeStore`] for tests and examples.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::convert::Infallible;

use strata_merkle::MerkleHash;

use super::index::NodePos;
use super::store::MmrNodeStore;

/// A non-persistent [`MmrNodeStore`] backed by a `BTreeMap`.
#[derive(Debug)]
pub struct MemMmr<H: MerkleHash> {
    nodes: RefCell<BTreeMap<NodePos, H>>,
}

impl<H: MerkleHash> Default for MemMmr<H> {
    fn default() -> Self {
        Self {
            nodes: RefCell::new(BTreeMap::new()),
        }
    }
}

impl<H: MerkleHash> MmrNodeStore for MemMmr<H> {
    type Hash = H;
    type Error = Infallible;

    fn get_node(&self, pos: NodePos) -> Result<Option<H>, Infallible> {
        Ok(self.nodes.borrow().get(&pos).copied())
    }

    fn put_node(&self, pos: NodePos, value: H) -> Result<(), Infallible> {
        self.nodes.borrow_mut().insert(pos, value);
        Ok(())
    }

    fn delete_node(&self, pos: NodePos) -> Result<(), Infallible> {
        self.nodes.borrow_mut().remove(&pos);
        Ok(())
    }
}
