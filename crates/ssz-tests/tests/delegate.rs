//! Stands in for a consumer crate that references delegate wrappers as external
//! containers in an ssz-gen schema.
//!
//! The `consumer` module declares what such a crate writes: the wrappers, and
//! the aliases naming their views. The view type is chosen by generated code, so
//! this contract cannot be covered by a unit test inside `strata-identifiers`.

#![allow(
    unused_crate_dependencies,
    reason = "dependencies are referenced by generated code"
)]

/// The declarations an adopting crate provides for its schema's external types.
mod consumer {
    use ssz::DecodeError;
    use ssz_types::{BitList, FixedVector, Optional};
    use strata_identifiers::{SszDelegate, SszDelegateRef, impl_ssz_via_delegate};

    pub(crate) use crate::ssz_generated::tests::ssz::delegate::Choice;
    use crate::ssz_generated::tests::ssz::delegate::{
        BoundedListSsz, PairSsz, StableDelegateSsz, WideDelegateSsz,
    };

    /// Wrapper whose conversion happens to always succeed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Pair {
        pub(crate) a: u64,
        pub(crate) b: u32,
    }

    impl SszDelegate for Pair {
        type Delegate = PairSsz;

        fn into_delegate(self) -> Self::Delegate {
            let Self { a, b } = self;
            PairSsz { a, b }
        }

        fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
            let PairSsz { a, b } = delegate;
            Ok(Self { a, b })
        }
    }

    impl_ssz_via_delegate!(Pair);

    pub(crate) type PairRef<'a> = SszDelegateRef<'a, Pair>;

    /// Wrapper whose delegate is a raw `[u8; N]`, viewed as `FixedBytesRef`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Tag(pub(crate) [u8; 32]);

    impl SszDelegate for Tag {
        type Delegate = [u8; 32];

        fn into_delegate(self) -> Self::Delegate {
            self.0
        }

        fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
            Ok(Self(delegate))
        }
    }

    impl_ssz_via_delegate!(Tag);

    pub(crate) type TagRef<'a> = SszDelegateRef<'a, Tag>;

    /// Refinement wrapper: only some `u64`s are valid amounts.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct CheckedAmount(u64);

    impl CheckedAmount {
        /// Largest accepted value.
        pub(crate) const MAX: u64 = 100;

        /// Builds a value, rejecting anything above [`MAX`](Self::MAX).
        pub(crate) fn new(value: u64) -> Result<Self, DecodeError> {
            if value <= Self::MAX {
                Ok(Self(value))
            } else {
                Err(DecodeError::BytesInvalid(format!(
                    "amount {value} exceeds {}",
                    Self::MAX
                )))
            }
        }
    }

    impl SszDelegate for CheckedAmount {
        type Delegate = u64;

        fn into_delegate(self) -> Self::Delegate {
            self.0
        }

        fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
            Self::new(delegate)
        }
    }

    impl_ssz_via_delegate!(CheckedAmount);

    pub(crate) type CheckedAmountRef<'a> = SszDelegateRef<'a, CheckedAmount>;

    /// Wrapper whose delegate is a container holding a bounded list, whose bound
    /// the delegate's view checks only on field access.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct BoundedList(pub(crate) Vec<u8>);

    impl SszDelegate for BoundedList {
        type Delegate = BoundedListSsz;

        fn into_delegate(self) -> Self::Delegate {
            BoundedListSsz {
                data: self.0.try_into().expect("within the list bound"),
            }
        }

        fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
            Ok(Self(delegate.data.to_vec()))
        }
    }

    impl_ssz_via_delegate!(BoundedList);

    pub(crate) type BoundedListRef<'a> = SszDelegateRef<'a, BoundedList>;

    /// Wrapper whose delegate is a `StableContainer` with `Optional` fields.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct StableDelegate {
        pub(crate) a: Option<u64>,
        pub(crate) bits: Option<Vec<bool>>,
    }

    impl SszDelegate for StableDelegate {
        type Delegate = StableDelegateSsz;

        fn into_delegate(self) -> Self::Delegate {
            let bits = match self.bits {
                Some(bits) => {
                    let mut list =
                        BitList::<32>::with_capacity(bits.len()).expect("within the bitlist bound");
                    for (i, bit) in bits.iter().enumerate() {
                        list.set(i, *bit).expect("index within capacity");
                    }
                    Optional::Some(list)
                }
                None => Optional::None,
            };
            StableDelegateSsz {
                a: match self.a {
                    Some(a) => Optional::Some(a),
                    None => Optional::None,
                },
                b: bits,
            }
        }

        fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
            Ok(Self {
                a: match delegate.a {
                    Optional::Some(a) => Some(a),
                    Optional::None => None,
                },
                bits: match delegate.b {
                    Optional::Some(list) => Some(list.iter().collect()),
                    Optional::None => None,
                },
            })
        }
    }

    impl_ssz_via_delegate!(StableDelegate);

    pub(crate) type StableDelegateRef<'a> = SszDelegateRef<'a, StableDelegate>;

    /// Wrapper whose delegate mixes a bitvector, a vector of containers, and a
    /// union with a null arm.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct WideDelegate {
        pub(crate) pairs: [Pair; 2],
        pub(crate) marks: Vec<bool>,
        pub(crate) tag: Choice,
        pub(crate) choice: Option<u64>,
    }

    impl SszDelegate for WideDelegate {
        type Delegate = WideDelegateSsz;

        fn into_delegate(self) -> Self::Delegate {
            WideDelegateSsz {
                pairs: FixedVector::new(
                    self.pairs
                        .into_iter()
                        .map(SszDelegate::into_delegate)
                        .collect::<Vec<_>>(),
                )
                .expect("exactly two pairs"),
                marks: {
                    let mut list = BitList::<16>::with_capacity(self.marks.len())
                        .expect("within the bitlist bound");
                    for (i, mark) in self.marks.iter().enumerate() {
                        list.set(i, *mark).expect("index within capacity");
                    }
                    list
                },
                tag: self.tag,
                choice: self.choice,
            }
        }

        fn from_delegate(delegate: Self::Delegate) -> Result<Self, DecodeError> {
            let pairs = delegate
                .pairs
                .iter()
                .cloned()
                .map(Pair::from_delegate)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Self {
                pairs: pairs.try_into().expect("exactly two pairs"),
                marks: delegate.marks.iter().collect(),
                tag: delegate.tag,
                choice: delegate.choice,
            })
        }
    }

    impl_ssz_via_delegate!(WideDelegate);

    pub(crate) type WideDelegateRef<'a> = SszDelegateRef<'a, WideDelegate>;
}

/// SSZ containers generated from `tests/ssz/delegate.ssz`.
#[allow(unreachable_pub, missing_docs, reason = "generated code")]
mod ssz_generated {
    include!(concat!(env!("OUT_DIR"), "/generated_delegate_ssz.rs"));
}

use ssz::Encode;
use ssz::view::{DecodeView, SszTypeInfo};
use ssz_types::view::ToOwnedSsz;
use tree_hash::{Sha256Hasher, TreeHash};

use crate::consumer::{
    BoundedList, BoundedListRef, CheckedAmount, CheckedAmountRef, Choice, Pair, PairRef,
    StableDelegate, StableDelegateRef, Tag, TagRef, WideDelegate, WideDelegateRef,
};
use crate::ssz_generated::tests::ssz::delegate::{
    BoundedListContainer, BoundedListContainerRef, ByteArrayContainer, ByteArrayContainerRef,
    RefinementContainer, RefinementContainerRef, RepresentationContainer,
    RepresentationContainerRef, RepresentationListContainer, RepresentationListContainerRef,
    StableDelegateContainer, StableDelegateContainerRef, WideDelegateContainer,
    WideDelegateContainerRef,
};

fn make_pair() -> Pair {
    Pair {
        a: 0x0102_0304,
        b: 0x0506,
    }
}

fn make_representation_container() -> RepresentationContainer {
    RepresentationContainer {
        pair: make_pair(),
        n: 9,
    }
}

fn make_refinement_container() -> RefinementContainer {
    RefinementContainer {
        amount: CheckedAmount::new(42).expect("within bound"),
        n: 7,
    }
}

/// The borrowing view resolves from the pragma and recovers the wrapper.
#[test]
fn representation_wrapper_field_resolves_to_borrowing_view() {
    let owned = make_representation_container();
    let bytes = owned.as_ssz_bytes();

    let view = RepresentationContainerRef::from_ssz_bytes(&bytes).expect("view decodes");
    let field: PairRef<'_> = view.pair().expect("field view decodes");

    assert_eq!(ToOwnedSsz::to_owned(&field), owned.pair);
    assert_eq!(view.to_owned(), owned);
}

/// The decoding adapter resolves from the pragma and recovers the wrapper.
#[test]
fn refinement_wrapper_field_resolves_to_decoding_view() {
    let owned = make_refinement_container();
    let bytes = owned.as_ssz_bytes();

    let view = RefinementContainerRef::from_ssz_bytes(&bytes).expect("view decodes");
    let field: CheckedAmountRef<'_> = view.amount().expect("field view decodes");

    assert_eq!(ToOwnedSsz::to_owned(&field), owned.amount);
    assert_eq!(view.to_owned(), owned);
}

/// A refinement wrapper rejects a valid delegate that is an invalid wrapper, as
/// an error rather than a panic — the case that forces decoding.
#[test]
fn refinement_view_rejects_valid_delegate_invalid_wrapper() {
    let over_bound = (CheckedAmount::MAX + 1).as_ssz_bytes();

    // Borrowing the delegate succeeds: the bytes are a valid `u64`.
    let view = <CheckedAmountRef<'_> as DecodeView>::from_ssz_bytes(&over_bound)
        .expect("delegate view borrows");

    // The wrapper's invariant is enforced on materialization.
    assert!(ToOwnedSsz::<CheckedAmount>::try_to_owned(&view).is_err());
}

/// The rejection propagates out of the enclosing container's `try_to_owned`.
#[test]
fn refinement_field_getter_rejects_invalid_wrapper() {
    let mut bytes = (CheckedAmount::MAX + 1).as_ssz_bytes();
    bytes.extend_from_slice(&7u64.as_ssz_bytes());

    let view = RefinementContainerRef::from_ssz_bytes(&bytes).expect("view decodes");

    let field = view.amount().expect("field view borrows");
    assert!(ToOwnedSsz::<CheckedAmount>::try_to_owned(&field).is_err());

    // Generated code propagates it with `?` rather than panicking.
    assert!(view.try_to_owned().is_err());
}

/// Both views report the wrapper's layout, so field offsets agree.
#[test]
fn views_report_wrapper_layout() {
    assert!(<PairRef<'_> as SszTypeInfo>::is_ssz_fixed_len());
    assert_eq!(
        <PairRef<'_> as SszTypeInfo>::ssz_fixed_len(),
        <Pair as Encode>::ssz_fixed_len(),
    );

    assert!(<CheckedAmountRef<'_> as SszTypeInfo>::is_ssz_fixed_len());
    assert_eq!(
        <CheckedAmountRef<'_> as SszTypeInfo>::ssz_fixed_len(),
        <CheckedAmount as Encode>::ssz_fixed_len(),
    );
}

/// The trailing field still decodes, so the views report the layout the encoder
/// used.
#[test]
fn trailing_fields_stay_aligned() {
    let rep_bytes = make_representation_container().as_ssz_bytes();
    let ref_bytes = make_refinement_container().as_ssz_bytes();

    let rep_view = RepresentationContainerRef::from_ssz_bytes(&rep_bytes).expect("decodes");
    let ref_view = RefinementContainerRef::from_ssz_bytes(&ref_bytes).expect("decodes");

    assert_eq!(rep_view.n().expect("trailing field"), 9);
    assert_eq!(ref_view.n().expect("trailing field"), 7);
}

/// Container roots are the same merkleized from the owned value or a view.
#[test]
fn container_views_merkleize_identically_to_owned() {
    let representation = make_representation_container();
    let refinement = make_refinement_container();
    let rep_bytes = representation.as_ssz_bytes();
    let ref_bytes = refinement.as_ssz_bytes();

    let rep_view = RepresentationContainerRef::from_ssz_bytes(&rep_bytes).expect("decodes");
    let ref_view = RefinementContainerRef::from_ssz_bytes(&ref_bytes).expect("decodes");

    assert_eq!(
        TreeHash::tree_hash_root::<Sha256Hasher>(&rep_view),
        TreeHash::tree_hash_root::<Sha256Hasher>(&representation),
    );
    assert_eq!(
        TreeHash::tree_hash_root::<Sha256Hasher>(&ref_view),
        TreeHash::tree_hash_root::<Sha256Hasher>(&refinement),
    );
}

/// A `List` of wrappers round-trips through the same path.
#[test]
fn list_of_wrappers_round_trips() {
    let owned = RepresentationListContainer {
        pairs: vec![make_pair(), make_pair()]
            .try_into()
            .expect("within the list bound"),
    };
    let bytes = owned.as_ssz_bytes();

    let view = RepresentationListContainerRef::from_ssz_bytes(&bytes).expect("view decodes");

    assert_eq!(view.to_owned(), owned);
}

/// A wrapper whose delegate is a raw `[u8; N]` borrows through
/// `FixedBytesRef`, via the delegate's `SszHasView` link.
#[test]
fn byte_array_delegate_resolves_to_borrowing_view() {
    let owned = ByteArrayContainer {
        tag: Tag([0xAB; 32]),
        n: 11,
    };
    let bytes = owned.as_ssz_bytes();

    let view = ByteArrayContainerRef::from_ssz_bytes(&bytes).expect("view decodes");
    let field: TagRef<'_> = view.tag().expect("field view decodes");

    assert_eq!(ToOwnedSsz::to_owned(&field), owned.tag);
    assert_eq!(view.n().expect("trailing field"), 11);
    assert_eq!(view.to_owned(), owned);
    assert_eq!(
        TreeHash::tree_hash_root::<Sha256Hasher>(&view),
        TreeHash::tree_hash_root::<Sha256Hasher>(&owned),
    );
}

/// A wrapper whose delegate holds a bounded list rejects an over-long list as
/// an error.
///
/// The delegate's container view checks only the offset table at decode, so a
/// borrowing adapter would accept these bytes and then panic in `to_owned`
/// when the list getter enforces the bound. Decoding surfaces it as `Err`.
#[test]
fn bounded_list_delegate_rejects_over_long_list() {
    // BoundedListSsz = { data: List[byte, 4] }: a 4-byte offset, then payload.
    let mut bytes = 4u32.as_ssz_bytes();
    bytes.extend_from_slice(&[0xAA; 5]);

    let view =
        <BoundedListRef<'_> as DecodeView>::from_ssz_bytes(&bytes).expect("delegate view borrows");

    assert!(ToOwnedSsz::<BoundedList>::try_to_owned(&view).is_err());
}

/// The same wrapper round-trips when the list is within its bound.
#[test]
fn bounded_list_delegate_round_trips_within_bound() {
    let owned = BoundedListContainer {
        bounded: BoundedList(vec![1, 2, 3]),
    };
    let bytes = owned.as_ssz_bytes();

    let view = BoundedListContainerRef::from_ssz_bytes(&bytes).expect("view decodes");

    assert_eq!(view.to_owned(), owned);
}

/// The same nine bytes that panic upstream's generated `to_owned` today.
#[test]
fn generated_try_to_owned_reports_deferred_bound_instead_of_panicking() {
    use crate::ssz_generated::tests::ssz::delegate::{BoundedListSsz, BoundedListSszRef};

    let mut bytes = 4u32.as_ssz_bytes();
    bytes.extend_from_slice(&[0xAA; 5]);

    let view = <BoundedListSszRef<'_> as DecodeView>::from_ssz_bytes(&bytes)
        .expect("offset table validates");

    let err = ToOwnedSsz::<BoundedListSsz>::try_to_owned(&view)
        .expect_err("over-long list must be reported, not panic");
    println!("PROBE: {err:?}");
}

/// A delegate that is a `StableContainer` with `Optional` fields round-trips
/// through the borrowing view.
#[test]
fn stable_container_delegate_round_trips() {
    let owned = StableDelegateContainer {
        stable: StableDelegate {
            a: Some(0x0102_0304),
            bits: Some(vec![true, false, true, true]),
        },
    };
    let bytes = owned.as_ssz_bytes();

    let view = StableDelegateContainerRef::from_ssz_bytes(&bytes).expect("view borrows");
    let field: StableDelegateRef<'_> = view.stable().expect("field view borrows");

    assert_eq!(
        ToOwnedSsz::<StableDelegate>::try_to_owned(&field).expect("materializes"),
        owned.stable
    );
    assert_eq!(view.try_to_owned().expect("materializes"), owned);
}

/// Absent optionals round-trip too, so the `Optional::None` arm is covered.
#[test]
fn stable_container_delegate_round_trips_with_absent_fields() {
    let owned = StableDelegateContainer {
        stable: StableDelegate {
            a: None,
            bits: None,
        },
    };
    let bytes = owned.as_ssz_bytes();

    let view = StableDelegateContainerRef::from_ssz_bytes(&bytes).expect("view borrows");

    assert_eq!(view.try_to_owned().expect("materializes"), owned);
}

/// A delegate holding a `Vector` of containers and a `Union[null, T]`.
#[test]
fn vector_and_union_delegate_round_trips() {
    for choice in [Some(7u64), None] {
        let owned = WideDelegateContainer {
            wide: WideDelegate {
                pairs: [make_pair(), Pair { a: 5, b: 6 }],
                marks: vec![true, false, true],
                tag: Choice::Selector1(0x0203),
                choice,
            },
        };
        let bytes = owned.as_ssz_bytes();

        let view = WideDelegateContainerRef::from_ssz_bytes(&bytes).expect("view borrows");
        let field: WideDelegateRef<'_> = view.wide().expect("field view borrows");

        assert_eq!(
            ToOwnedSsz::<WideDelegate>::try_to_owned(&field).expect("materializes"),
            owned.wide
        );
        assert_eq!(view.try_to_owned().expect("materializes"), owned);
    }
}

/// Both new views merkleize identically to their owned counterparts.
#[test]
fn new_delegate_views_merkleize_identically_to_owned() {
    let stable = StableDelegateContainer {
        stable: StableDelegate {
            a: Some(1),
            bits: Some(vec![true, true]),
        },
    };
    let stable_bytes = stable.as_ssz_bytes();
    let stable_view =
        StableDelegateContainerRef::from_ssz_bytes(&stable_bytes).expect("view borrows");
    assert_eq!(
        TreeHash::tree_hash_root::<Sha256Hasher>(&stable_view),
        TreeHash::tree_hash_root::<Sha256Hasher>(&stable),
    );

    let wide = WideDelegateContainer {
        wide: WideDelegate {
            pairs: [make_pair(), make_pair()],
            marks: vec![false, true],
            tag: Choice::Selector0(9),
            choice: Some(3),
        },
    };
    let wide_bytes = wide.as_ssz_bytes();
    let wide_view = WideDelegateContainerRef::from_ssz_bytes(&wide_bytes).expect("view borrows");
    assert_eq!(
        TreeHash::tree_hash_root::<Sha256Hasher>(&wide_view),
        TreeHash::tree_hash_root::<Sha256Hasher>(&wide),
    );
}

/// An out-of-range union selector is reported as an error rather than panicking.
#[test]
fn union_rejects_out_of_range_selector() {
    use crate::ssz_generated::tests::ssz::delegate::{Choice, ChoiceRef};

    // Selector 9 on a two-arm union, then a payload byte.
    let bytes = [9u8, 0u8];

    let view = <ChoiceRef<'_> as DecodeView>::from_ssz_bytes(&bytes).expect("view borrows");

    let err = ToOwnedSsz::<Choice>::try_to_owned(&view)
        .expect_err("invalid selector must be reported, not panic");
    println!("PROBE union: {err:?}");
}
