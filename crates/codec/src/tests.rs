#![allow(unreachable_pub)] // testing the macro
#![expect(unused)] // testing the macro

use crate::impl_type_flat_struct;

impl_type_flat_struct! {
    #[derive(Ord, PartialOrd)]
    pub struct Coordinate {
        x: i32,
        y: i32,
        theta: u16,
    }
}
