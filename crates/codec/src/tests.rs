#![allow(unreachable_pub)] // testing the macro
#![expect(unused)] // testing the macro

use crate::{encode_to_vec, impl_type_flat_struct};

impl_type_flat_struct! {
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
    pub struct Coordinate {
        x: i32,
        y: i32,
        theta: u16,
    }

}

#[test]
fn test_macro_gen() {
    let c = Coordinate {
        x: 1,
        y: -2,
        theta: 12345,
    };

    let t1 = (12345u16 >> 8) as u8;
    let t2 = (12345u16 & 0xff) as u8;

    let f = format!("{c:?}");
    assert_eq!(f, "Coordinate { x: 1, y: -2, theta: 12345 }");

    let c2 = Coordinate {
        x: -1,
        y: -2,
        theta: 23456,
    };

    assert_ne!(c, c2);

    let b = encode_to_vec(&c).expect("test: encode_to_vec");
    assert_eq!(&b, &[0, 0, 0, 1, 0xff, 0xff, 0xff, 0xfe, t1, t2]);
}
