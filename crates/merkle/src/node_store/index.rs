//! MMR node-index math: positions, leaf↔node mapping, and peak computation.
//!
//! Ported from alpen's `mmr_index` / `mmr_algorithm`, kept storage- and
//! namespace-agnostic. A node lives at `(height, index)`: leaves are height 0,
//! and `index` is the zero-based offset within that level.

/// Height of the reserved metadata level.
///
/// A real MMR node never reaches this height (it would require `2^255` leaves),
/// so metadata records (e.g. the leaf count) never collide with node keys.
const META_HEIGHT: u8 = u8::MAX;

/// Structured position of a node in an MMR, given by `(height, index)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NodePos {
    height: u8,
    index: u64,
}

impl NodePos {
    /// Constructs a node position from height and index.
    pub fn new(height: u8, index: u64) -> Self {
        Self { height, index }
    }

    /// Returns the height of this node (0 = leaf).
    pub fn height(self) -> u8 {
        self.height
    }

    /// Returns the zero-based index within this node's level.
    pub fn index(self) -> u64 {
        self.index
    }

    /// Returns this node's parent position.
    ///
    /// Panics on height overflow, which a real tree never reaches.
    pub fn parent(self) -> Self {
        assert!(self.height < u8::MAX, "NodePos::parent height overflow");
        Self {
            height: self.height + 1,
            index: self.index >> 1,
        }
    }

    /// Returns true if this node is the left child of its parent.
    pub fn is_left_child(self) -> bool {
        self.index.is_multiple_of(2)
    }

    /// Returns this node's sibling (same height, index toggled).
    pub fn sibling(self) -> Self {
        Self {
            height: self.height,
            index: self.index ^ 1,
        }
    }

    /// Returns the reserved metadata slot for `tag`, outside the node space.
    pub fn meta(tag: u64) -> Self {
        Self {
            height: META_HEIGHT,
            index: tag,
        }
    }

    /// Returns a stable, order-preserving storage key: `height || index_be`.
    pub fn to_key(self) -> [u8; 9] {
        let mut key = [0u8; 9];
        key[0] = self.height;
        key[1..].copy_from_slice(&self.index.to_be_bytes());
        key
    }
}

/// Zero-based index of a leaf in an MMR (always height 0).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LeafPos(u64);

impl LeafPos {
    /// Constructs a leaf position from a zero-based leaf index.
    pub fn new(index: u64) -> Self {
        Self(index)
    }

    /// Returns the zero-based leaf index.
    pub fn index(self) -> u64 {
        self.0
    }

    /// Returns this leaf's position in the node tree (height 0).
    pub fn node_pos(self) -> NodePos {
        NodePos::new(0, self.0)
    }
}

/// Size (in leaves) of the highest perfect mountain that fits in `leaves`.
fn highest_mountain_size(leaves: u64) -> u64 {
    debug_assert!(leaves > 0, "highest_mountain_size: leaves must be > 0");
    1u64 << (63 - leaves.leading_zeros())
}

/// Returns the peak positions for an MMR of `leaf_count` leaves, left to right.
pub fn peak_positions(leaf_count: u64) -> Vec<NodePos> {
    let mut peaks = Vec::new();
    let mut start_leaf = 0u64;
    let mut remaining = leaf_count;

    while remaining > 0 {
        let size = highest_mountain_size(remaining);
        let height = size.trailing_zeros() as u8;
        peaks.push(NodePos::new(height, start_leaf >> height));
        start_leaf += size;
        remaining -= size;
    }

    peaks
}

/// Returns the peak node that the leaf at `leaf_index` hashes up to, in an MMR
/// of `leaf_count` leaves.
///
/// The caller must ensure `leaf_index < leaf_count`.
pub fn peak_for_leaf(leaf_index: u64, leaf_count: u64) -> NodePos {
    debug_assert!(
        leaf_index < leaf_count,
        "peak_for_leaf: leaf_index out of range"
    );

    let mut start_leaf = 0u64;
    let mut remaining = leaf_count;

    while remaining > 0 {
        let size = highest_mountain_size(remaining);
        let end_leaf = start_leaf + size;
        if leaf_index < end_leaf {
            let height = size.trailing_zeros() as u8;
            return NodePos::new(height, start_leaf >> height);
        }
        start_leaf = end_leaf;
        remaining -= size;
    }

    unreachable!("peak_for_leaf: leaf_index < leaf_count guarantees a peak")
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Strategy for a node position within a realistic height/index range.
    fn node_pos() -> impl Strategy<Value = NodePos> {
        (0u8..=10, 0u64..1024).prop_map(|(h, i)| NodePos::new(h, i))
    }

    // Concrete examples that document exact peak decompositions.
    #[test]
    fn peaks_match_known_decompositions() {
        assert_eq!(peak_positions(0), vec![]);
        assert_eq!(peak_positions(1), vec![NodePos::new(0, 0)]);
        assert_eq!(
            peak_positions(3),
            vec![NodePos::new(1, 0), NodePos::new(0, 2)]
        );
        assert_eq!(peak_positions(4), vec![NodePos::new(2, 0)]);
        assert_eq!(
            peak_positions(11),
            vec![NodePos::new(3, 0), NodePos::new(1, 4), NodePos::new(0, 10)]
        );
    }

    #[test]
    fn meta_slot_never_collides_with_real_nodes() {
        let meta = NodePos::meta(0).to_key();
        // No real node (height well under META_HEIGHT) shares the meta key.
        for height in 0u8..64 {
            assert_ne!(NodePos::new(height, u64::MAX).to_key(), meta);
        }
    }

    proptest! {
        #[test]
        fn node_relations_follow_bit_math(height in 0u8..63, index in any::<u64>()) {
            let node = NodePos::new(height, index);
            prop_assert_eq!(node.parent(), NodePos::new(height + 1, index >> 1));
            prop_assert_eq!(node.sibling(), NodePos::new(height, index ^ 1));
            prop_assert_eq!(node.is_left_child(), index % 2 == 0);
            // Sibling is its own inverse.
            prop_assert_eq!(node.sibling().sibling(), node);
        }

        #[test]
        fn key_order_matches_position_order(a in node_pos(), b in node_pos()) {
            prop_assert_eq!(
                a.to_key().cmp(&b.to_key()),
                (a.height(), a.index()).cmp(&(b.height(), b.index()))
            );
        }

        #[test]
        fn peaks_partition_leaves_with_descending_heights(leaf_count in 0u64..1_000_000) {
            let peaks = peak_positions(leaf_count);
            // Each peak of height h covers 2^h leaves; together they cover all.
            let covered: u64 = peaks.iter().map(|p| 1u64 << p.height()).sum();
            prop_assert_eq!(covered, leaf_count);
            for pair in peaks.windows(2) {
                prop_assert!(pair[0].height() > pair[1].height());
            }
        }

        #[test]
        fn peak_for_leaf_is_a_reachable_peak(leaf_count in 1u64..1_000_000, frac in any::<u64>()) {
            let leaf_index = frac % leaf_count;
            let peak = peak_for_leaf(leaf_index, leaf_count);
            prop_assert!(peak_positions(leaf_count).contains(&peak));

            // Walking up from the leaf reaches exactly that peak.
            let mut cur = LeafPos::new(leaf_index).node_pos();
            let mut steps = 0u32;
            while cur != peak {
                cur = cur.parent();
                steps += 1;
                prop_assert!(steps <= 64, "walk did not terminate");
            }
            prop_assert_eq!(cur, peak);
        }
    }
}
