//! Merkle mountain range implementation crate.
#![expect(
    clippy::declare_interior_mutable_const,
    reason = "Constants with interior mutability are needed for MMR implementation"
)]
#![expect(
    clippy::borrow_interior_mutable_const,
    reason = "Borrowing interior mutable constants is required for MMR operations"
)]

pub mod error;
pub mod hasher;

use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use error::MerkleError;
use hasher::{DigestMerkleHasher, MerkleHash, MerkleHasher};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha256;

/// Merkle hash impl for SHA-256 `Digest` impl.
pub type Sha256Hasher = DigestMerkleHasher<Sha256, 32>;

/// Compact representation of the MMR that should be borsh serializable easily.
#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct CompactMmr<H: MerkleHash> {
    entries: u64,
    cap_log2: u8,
    roots: Vec<H>,
}

impl<H> Serialize for CompactMmr<H>
where
    H: MerkleHash + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (&self.entries, &self.cap_log2, &self.roots).serialize(serializer)
    }
}

impl<'de, H> Deserialize<'de> for CompactMmr<H>
where
    H: MerkleHash + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (entries, cap_log2, roots) = <(u64, u8, Vec<H>)>::deserialize(deserializer)?;
        Ok(Self {
            entries,
            cap_log2,
            roots,
        })
    }
}

/// Merkle mountain range that can hold up to 2**64 elements.
#[derive(Clone, Debug)]
pub struct MerkleMr64<MH: MerkleHasher + Clone> {
    /// Total number of elements inserted into MMR.
    pub(crate) num: u64,

    /// Buffer of all possible peaks in MMR.  Only some of these will be valid
    /// at a time.
    pub(crate) peaks: Box<[MH::Hash]>,

    /// phantom data for hasher
    _pd: PhantomData<MH>,
}

impl<MH: MerkleHasher + Clone> MerkleMr64<MH> {
    /// Constructs a new MMR with some scale.  This is the number of peaks we
    /// will keep in the MMR.  The real capacity is 2**n of this value
    /// specified.
    ///
    /// # Panics
    ///
    /// If the `cap_log2` parameter is larger than 64.
    pub fn new(cap_log2: usize) -> Self {
        if cap_log2 > 64 {
            panic!("mmr: tried to create MMR of size {cap_log2} (max is 64)");
        }

        Self {
            num: 0,
            peaks: vec![MH::zero_hash(); cap_log2].into_boxed_slice(),
            _pd: PhantomData,
        }
    }

    /// Gets the number of entries inserted into the MMR.
    pub fn num_entries(&self) -> u64 {
        self.num
    }

    /// Returns an iterator over the set merkle peaks, exposing their height.
    ///
    /// This is mainly useful for testing/troubleshooting.
    pub fn peaks_iter(&self) -> impl Iterator<Item = (u8, &MH::Hash)> {
        self.peaks
            .iter()
            .enumerate()
            .filter(|(_, h)| !<MH::Hash as MerkleHash>::is_zero(h))
            .map(|(i, h)| (i as u8, h))
    }

    /// Gets if there have been no entries inserted into the MMR.
    pub fn is_empty(&self) -> bool {
        self.num_entries() == 0
    }

    /// Unpacks the MMR from a compact form.
    pub fn from_compact(compact: &CompactMmr<MH::Hash>) -> Self {
        // FIXME this is somewhat inefficient, we could consume the vec and just
        // slice out its elements, but this is fine for now
        let mut roots = vec![MH::zero_hash(); compact.cap_log2 as usize];
        let mut at = 0;
        for i in 0..compact.cap_log2 {
            if (compact.entries >> i) & 1 != 0 {
                roots[i as usize] = compact.roots[at as usize];
                at += 1;
            }
        }

        Self {
            num: compact.entries,
            peaks: roots.into(),
            _pd: PhantomData,
        }
    }

    /// Converts the MMR to a compact form.
    pub fn to_compact(&self) -> CompactMmr<MH::Hash> {
        CompactMmr {
            entries: self.num,
            cap_log2: self.peaks.len() as u8,
            roots: self
                .peaks
                .iter()
                .filter(|h| !<MH::Hash as MerkleHash>::is_zero(*h))
                .copied()
                .collect(),
        }
    }

    /// Returns the total number of elements we're allowed to insert into the
    /// MMR, based on the roots size.
    pub fn max_capacity(&self) -> u64 {
        // Very clean bit manipulation.
        match self.peaks.len() as u64 {
            0 => 0,
            peaks => u64::MAX >> (64 - peaks),
        }
    }

    /// Checks if we can insert a new element.  Returns error if not.
    fn check_capacity(&self) -> Result<(), MerkleError> {
        if self.num == self.max_capacity() {
            return Err(MerkleError::MaxCapacity);
        }
        Ok(())
    }

    /// Adds a new leaf to the MMR.
    pub fn add_leaf(&mut self, leaf: MH::Hash) -> Result<(), MerkleError> {
        self.check_capacity()?;

        if self.num == 0 {
            self.peaks[0] = leaf;
            self.num += 1;
            return Ok(());
        }

        // the number of elements in MMR is also the mask of peaks
        let peak_mask = self.num;

        // Iterate through the height.
        let mut current_node = leaf;
        let mut current_height = 0;
        while (peak_mask >> current_height) & 1 == 1 {
            let next_node = MH::hash_node(self.peaks[current_height], current_node);

            // setting this for debugging purpose
            self.peaks[current_height] = MH::zero_hash();

            current_node = next_node;
            current_height += 1;
        }

        self.peaks[current_height] = current_node;
        self.num += 1;

        Ok(())
    }

    /// If the MMR has a power-of-2 number of elements, then this extracts the
    /// single populated root that commits to all of them.
    pub fn get_single_root(&self) -> Result<MH::Hash, MerkleError> {
        if self.num == 0 {
            return Err(MerkleError::NoElements);
        }

        if !self.num.is_power_of_two() && self.num != 1 {
            return Err(MerkleError::NotPowerOfTwo);
        }

        Ok(self.peaks[(self.num.ilog2()) as usize])
    }

    /// Adds a new leaf, returning an updated version of the proof passed.  If
    /// the proof passed does not match the accumulator, then the returned proof
    /// will be nonsensical.
    // TODO make a version of this that doesn't alloc?
    pub fn add_leaf_updating_proof(
        &mut self,
        next: MH::Hash,
        proof: &MerkleProof<MH::Hash>,
    ) -> Result<MerkleProof<MH::Hash>, MerkleError> {
        self.check_capacity()?;

        // FIXME this is a weird function to call if this is true, since how
        // could a valid proof have been passed?
        if self.num == 0 {
            self.add_leaf(next)?;
            return Ok(MerkleProof::new_zero());
        }

        let mut updated_proof = proof.clone();

        let new_leaf_index = self.num;
        let peak_mask = self.num;
        let mut current_node = next;
        let mut current_height = 0;
        while (peak_mask >> current_height) & 1 == 1 {
            let prev_node = self.peaks[current_height];
            let next_node = MH::hash_node(prev_node, current_node);
            let leaf_parent_tree = new_leaf_index >> (current_height + 1);

            let proof_index = updated_proof.index();
            self.update_single_proof(
                updated_proof.inner_mut(),
                proof_index,
                leaf_parent_tree,
                current_height,
                prev_node,
                current_node,
            );

            self.peaks[current_height] = MH::zero_hash();
            current_node = next_node;
            current_height += 1;
        }

        self.peaks[current_height] = current_node;
        self.num += 1;

        Ok(updated_proof)
    }

    fn update_single_proof(
        &mut self,
        proof: &mut RawMerkleProof<MH::Hash>,
        proof_index: u64,
        leaf_parent_tree: u64,
        current_height: usize,
        prev_node: MH::Hash,
        current_node: MH::Hash,
    ) {
        let proof_parent_tree = proof_index >> (current_height + 1);
        if leaf_parent_tree == proof_parent_tree {
            let cohashes = proof.cohashes_vec_mut();

            if current_height >= cohashes.len() {
                cohashes.resize(current_height + 1, MH::zero_hash());
            }

            if (proof_index >> current_height) & 1 == 1 {
                cohashes[current_height] = prev_node;
            } else {
                cohashes[current_height] = current_node;
            }
        }
    }

    /// Adds a leaf to the accumulator, updating the proofs in a provided list
    /// of proofs in-place, and returning a proof to the new leaf.
    pub fn add_leaf_updating_proof_list(
        &mut self,
        next: MH::Hash,
        proof_list: &mut [MerkleProof<MH::Hash>],
    ) -> Result<MerkleProof<MH::Hash>, MerkleError> {
        self.check_capacity()?;

        if self.num == 0 {
            self.add_leaf(next)?;
            return Ok(MerkleProof::new_zero());
        }

        let mut new_proof = MerkleProof::<MH::Hash>::new_empty(self.num);
        let new_proof_index = new_proof.index();
        assert_eq!(new_proof_index, self.num);

        let new_leaf_index = self.num;
        let peak_mask = self.num;
        let mut current_node = next;
        let mut current_height = 0;
        while (peak_mask >> current_height) & 1 == 1 {
            let prev_node = self.peaks[current_height];
            let next_node = MH::hash_node(prev_node, current_node);
            let leaf_parent_tree = new_leaf_index >> (current_height + 1);

            for proof in proof_list.iter_mut() {
                let index = proof.index();
                self.update_single_proof(
                    proof.inner_mut(),
                    index,
                    leaf_parent_tree,
                    current_height,
                    prev_node,
                    current_node,
                );
            }

            self.update_single_proof(
                new_proof.inner_mut(),
                new_proof_index,
                leaf_parent_tree,
                current_height,
                prev_node,
                current_node,
            );

            // the peaks value is no longer needed
            self.peaks[current_height] = MH::zero_hash();
            current_node = next_node;
            current_height += 1;
        }

        self.peaks[current_height] = current_node;
        self.num += 1;

        Ok(new_proof)
    }

    /// Verifies a single proof for a leaf against the current MMR state.
    pub fn verify(&self, proof: &MerkleProof<MH::Hash>, leaf: &MH::Hash) -> bool {
        self.verify_raw(proof.cohashes(), proof.index(), leaf)
    }

    fn verify_raw(&self, cohashes: &[MH::Hash], leaf_index: u64, leaf_hash: &MH::Hash) -> bool {
        let root = &self.peaks[cohashes.len()];

        if cohashes.is_empty() {
            return <MH::Hash as MerkleHash>::eq_ct(root, leaf_hash);
        }

        let mut cur_hash = *leaf_hash;
        let mut side_flags = leaf_index;

        for cohash in cohashes.iter() {
            let node_hash = if side_flags & 1 == 1 {
                MH::hash_node(*cohash, cur_hash)
            } else {
                MH::hash_node(cur_hash, *cohash)
            };

            side_flags >>= 1;
            cur_hash = node_hash;
        }

        <MH::Hash as MerkleHash>::eq_ct(&cur_hash, root)
    }

    #[allow(dead_code, clippy::allow_attributes, reason = "used for testing")]
    pub(crate) fn gen_proof(
        &self,
        proof_list: &[MerkleProof<MH::Hash>],
        index: u64,
    ) -> Result<Option<MerkleProof<MH::Hash>>, MerkleError> {
        if index > self.num {
            return Err(MerkleError::IndexOutOfBounds);
        }

        match proof_list.iter().find(|proof| proof.index == index) {
            Some(proof) => Ok(Some(proof.clone())),
            None => Ok(None),
        }
    }
}

/// Proof for an entry in an MMR/tree.
///
/// If the MMR that produced this proof is updated, then this proof has to be
/// updated as well.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MerkleProof<H>
where
    H: MerkleHash,
{
    /// Sibling hashes required for proof.
    pub(crate) inner: RawMerkleProof<H>,

    /// Index of the element for which this proof is for.
    pub(crate) index: u64,
}

impl<H: MerkleHash> MerkleProof<H> {
    fn new(inner: RawMerkleProof<H>, index: u64) -> Self {
        Self { inner, index }
    }

    /// Constructs a new empty proof for the 0 index.
    pub fn new_zero() -> Self {
        Self::new_empty(0)
    }

    /// Constructs a new empty proof for some index.  This probably will not
    /// validate properly.
    fn new_empty(index: u64) -> Self {
        Self::new(RawMerkleProof::new_zero(), index)
    }

    /// Constructs a new instance from the path.
    pub fn from_cohashes(cohashes: Vec<H>, index: u64) -> Self {
        Self::new(RawMerkleProof::new(cohashes), index)
    }

    /// Exposes the raw inner proof, which you probably don't want to use.
    pub fn inner_raw(&self) -> &RawMerkleProof<H> {
        &self.inner
    }

    fn inner_mut(&mut self) -> &mut RawMerkleProof<H> {
        &mut self.inner
    }

    pub fn cohashes(&self) -> &[H] {
        self.inner.cohashes()
    }

    pub fn index(&self) -> u64 {
        self.index
    }

    /// Discards the index and returns the raw merkle proof.
    pub fn into_raw(self) -> RawMerkleProof<H> {
        self.inner
    }
}

/// Raw proof for some entry in a MMR/tree.
///
/// This doesn't include the index of the entry being proven, which makes this
/// useful in contexts where we establish that value separately.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RawMerkleProof<H>
where
    H: MerkleHash,
{
    pub(crate) cohashes: Vec<H>,
}

impl<H: MerkleHash> RawMerkleProof<H> {
    pub fn new(cohashes: Vec<H>) -> Self {
        Self { cohashes }
    }

    pub fn new_zero() -> Self {
        Self::new(Vec::new())
    }

    pub fn cohashes(&self) -> &[H] {
        &self.cohashes
    }

    fn cohashes_vec_mut(&mut self) -> &mut Vec<H> {
        &mut self.cohashes
    }

    /// Takes an index that this merkle proof is allegedly for and constructs a
    /// full proof using the cohash path we have.
    pub fn into_indexed(self, idx: u64) -> MerkleProof<H> {
        MerkleProof::from_cohashes(self.cohashes, idx)
    }
}

#[cfg(test)]
mod test {
    use sha2::{Digest, Sha256};

    use super::{MerkleMr64, MerkleProof, Sha256Hasher};
    use crate::error::MerkleError;

    type Hash32 = [u8; 32];

    fn generate_for_n_integers(n: usize) -> (MerkleMr64<Sha256Hasher>, Vec<MerkleProof<Hash32>>) {
        let mut mmr: MerkleMr64<Sha256Hasher> = MerkleMr64::new(14);

        let mut proof = Vec::new();
        let list_of_hashes = generate_hashes_for_n_integers(n);

        (0..n).for_each(|i| {
            let new_proof = mmr
                .add_leaf_updating_proof_list(list_of_hashes[i], &mut proof)
                .expect("test: add leaf");
            proof.push(new_proof);
        });
        (mmr, proof)
    }

    fn generate_hashes_for_n_integers(n: usize) -> Vec<Hash32> {
        (0..n)
            .map(|i| Sha256::digest(i.to_be_bytes()).into())
            .collect::<Vec<Hash32>>()
    }

    fn mmr_proof_for_specific_nodes(n: usize, specific_nodes: Vec<u64>) {
        let (mmr, proof_list) = generate_for_n_integers(n);
        let proof: Vec<MerkleProof<Hash32>> = specific_nodes
            .iter()
            .map(|i| {
                mmr.gen_proof(&proof_list, *i)
                    .unwrap()
                    .expect("cannot find proof for the given index")
            })
            .collect();

        let hash: Vec<Hash32> = specific_nodes
            .iter()
            .map(|i| Sha256::digest(i.to_be_bytes()).into())
            .collect();

        (0..specific_nodes.len()).for_each(|i| {
            assert!(mmr.verify(&proof[i], &hash[i]));
        });
    }

    #[test]
    fn check_zero_elements() {
        mmr_proof_for_specific_nodes(0, vec![]);
    }

    #[test]
    fn check_two_sibling_leaves() {
        mmr_proof_for_specific_nodes(11, vec![4, 5]);
        mmr_proof_for_specific_nodes(11, vec![5, 6]);
    }

    #[test]
    fn check_single_element() {
        let (mmr, proof_list) = generate_for_n_integers(1);

        let proof = mmr
            .gen_proof(&proof_list, 0)
            .unwrap()
            .expect("Didn't find proof for given index");

        let hash = Sha256::digest(0_usize.to_be_bytes()).into();
        assert!(mmr.verify(&proof, &hash));
    }

    #[test]
    fn check_two_peaks() {
        mmr_proof_for_specific_nodes(3, vec![0, 2]);
    }

    #[test]
    fn check_500_elements() {
        mmr_proof_for_specific_nodes(500, vec![0, 456]);
    }

    #[test]
    fn check_peak_for_mmr_single_leaf() {
        let hashed1: Hash32 = Sha256::digest(b"first").into();

        let mut mmr: MerkleMr64<Sha256Hasher> = MerkleMr64::new(14);
        mmr.add_leaf(hashed1).expect("test: add leaf");

        assert_eq!(
            mmr.get_single_root(),
            Ok([
                167, 147, 123, 100, 184, 202, 165, 143, 3, 114, 27, 182, 186, 207, 92, 120, 203,
                35, 95, 235, 224, 231, 11, 27, 132, 205, 153, 84, 20, 97, 160, 142
            ])
        );
    }

    #[test]
    fn check_peak_for_mmr_three_leaves() {
        let hashed1: Hash32 = Sha256::digest(b"first").into();

        let mut mmr: MerkleMr64<Sha256Hasher> = MerkleMr64::new(14);
        mmr.add_leaf(hashed1).expect("test: add leaf");
        mmr.add_leaf(hashed1).expect("test: add leaf");
        mmr.add_leaf(hashed1).expect("test: add leaf");

        assert_eq!(mmr.get_single_root(), Err(MerkleError::NotPowerOfTwo));
    }

    #[test]
    fn check_peak_for_mmr_four_leaves() {
        let hashed1: Hash32 = Sha256::digest(b"first").into();

        let mut mmr: MerkleMr64<Sha256Hasher> = MerkleMr64::new(14);
        mmr.add_leaf(hashed1).expect("test: add leaf");
        mmr.add_leaf(hashed1).expect("test: add leaf");
        mmr.add_leaf(hashed1).expect("test: add leaf");
        mmr.add_leaf(hashed1).expect("test: add leaf");

        assert_eq!(
            mmr.get_single_root(),
            Ok([
                219, 107, 224, 125, 80, 152, 167, 72, 126, 25, 33, 96, 163, 0, 115, 13, 185, 247,
                54, 143, 195, 73, 7, 39, 95, 68, 14, 90, 198, 145, 216, 71
            ])
        );
    }

    #[test]
    fn check_invalid_proof() {
        let (mmr, _) = generate_for_n_integers(5);
        let invalid_proof = MerkleProof::<Hash32>::new_empty(6);
        let hash = Sha256::digest(42usize.to_be_bytes()).into();
        assert!(!mmr.verify(&invalid_proof, &hash));
    }

    #[test]
    fn check_add_node_and_update() {
        let mut mmr: MerkleMr64<Sha256Hasher> = MerkleMr64::new(14);
        let mut proof_list = Vec::new();

        let hashed0: Hash32 = Sha256::digest(b"first").into();
        let hashed1: Hash32 = Sha256::digest(b"second").into();
        let hashed2: Hash32 = Sha256::digest(b"third").into();
        let hashed3: Hash32 = Sha256::digest(b"fourth").into();
        let hashed4: Hash32 = Sha256::digest(b"fifth").into();

        let new_proof = mmr
            .add_leaf_updating_proof_list(hashed0, &mut proof_list)
            .expect("test: add leaf");
        proof_list.push(new_proof);

        let new_proof = mmr
            .add_leaf_updating_proof_list(hashed1, &mut proof_list)
            .expect("test: add leaf");
        proof_list.push(new_proof);

        let new_proof = mmr
            .add_leaf_updating_proof_list(hashed2, &mut proof_list)
            .expect("test: add leaf");
        proof_list.push(new_proof);

        let new_proof = mmr
            .add_leaf_updating_proof_list(hashed3, &mut proof_list)
            .expect("test: add leaf");
        proof_list.push(new_proof);

        let new_proof = mmr
            .add_leaf_updating_proof_list(hashed4, &mut proof_list)
            .expect("test: add leaf");
        proof_list.push(new_proof);

        assert!(mmr.verify(&proof_list[0], &hashed0));
        assert!(mmr.verify(&proof_list[1], &hashed1));
        assert!(mmr.verify(&proof_list[2], &hashed2));
        assert!(mmr.verify(&proof_list[3], &hashed3));
        assert!(mmr.verify(&proof_list[4], &hashed4));
    }

    #[test]
    fn check_compact_and_non_compact() {
        let (mmr, _) = generate_for_n_integers(5);

        let compact_mmr = mmr.to_compact();
        let deserialized_mmr = MerkleMr64::<Sha256Hasher>::from_compact(&compact_mmr);

        assert_eq!(mmr.num, deserialized_mmr.num);
        assert_eq!(mmr.peaks, deserialized_mmr.peaks);
    }

    #[test]
    fn arbitrary_index_proof() {
        let (mut mmr, _) = generate_for_n_integers(20);
        // update proof for 21st element
        let mut proof: MerkleProof<Hash32> = MerkleProof::new_empty(20);

        // add 4 elements into mmr, so 20 + 4 elements
        let num_elems = 4;
        let num_hash = generate_hashes_for_n_integers(num_elems);

        for elem in num_hash.iter().take(num_elems) {
            let new_proof = mmr
                .add_leaf_updating_proof(*elem, &proof)
                .expect("test: add leaf");
            proof = new_proof;
        }

        assert!(mmr.verify(&proof, &num_hash[0]));
    }

    #[test]
    fn update_proof_list_from_arbitrary_index() {
        let (mut mmr, _) = generate_for_n_integers(20);
        // update proof for 21st element
        let mut proof_list = Vec::new();

        // add 4 elements into mmr, so 20 + 4 elements
        let num_elems = 4;
        let num_hash = generate_hashes_for_n_integers(num_elems);

        for elem in num_hash.iter().take(num_elems) {
            let new_proof = mmr
                .add_leaf_updating_proof_list(*elem, &mut proof_list)
                .expect("test: add leaf");
            proof_list.push(new_proof);
        }

        for i in 0..num_elems {
            assert!(mmr.verify(&proof_list[i], &num_hash[i]));
        }
    }
}
