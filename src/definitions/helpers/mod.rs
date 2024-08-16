pub mod bytestr;
pub mod non_empty_map;
pub mod non_empty_vec;
pub mod tag24;

pub use bytestr::ByteStr;
pub use non_empty_map::NonEmptyMap;
pub use non_empty_vec::NonEmptyVec;
pub use tag24::Tag24;

pub(crate) fn get_value(value: ciborium::Value) -> coset::Result<ciborium::Value> {
    Ok(value)
}
