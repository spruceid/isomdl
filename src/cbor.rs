use std::cmp::Ordering;
use std::collections::BTreeMap;

use ciborium::value::Integer;
use ciborium::Value;
use coset::{AsCborValue, CborSerializable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cose::tag::{BIGNEG, BIGPOS};

pub mod to_cbor;

pub enum Error {
    Deserialize(&'static str),
    Seserialize(&'static str),
}

/// Wraps [chromium::Value] that implements [PartialEq], [Eq], [PartialOrd] and [Ord]
/// so it can be used in maps and sets.
///
/// Useful if in future we want to change the CBOR library.
#[derive(Debug, Clone)]
pub enum CborValue {
    /// Represents the absence of a value or the value undefined.
    Null,
    /// Represents a boolean value.
    Bool(bool),
    /// Integer CBOR numbers.
    ///
    /// The biggest value that can be represented is 2^64 - 1.
    /// While the smallest value is -2^64.
    /// Values outside this range can't be serialized
    /// and will cause an error.
    Integer(i128),
    /// Represents a floating point value.
    Float(f64),
    /// Represents a byte string.
    Bytes(Vec<u8>),
    /// Represents an UTF-8 encoded string.
    Text(String),
    /// Represents an array of values.
    Array(Vec<CborValue>),
    /// Represents a map.
    ///
    /// Maps are also called tables, dictionaries, hashes, or objects (in JSON).
    /// While any value can be used as a CBOR key
    /// it is better to use only one type of key in a map
    /// to avoid ambiguity.
    /// If floating point values are used as keys they are compared bit-by-bit for equality.
    /// If arrays or maps are used as keys the comparisons
    /// to establish canonical order may be slow and therefore insertion
    /// and retrieval of values will be slow too.
    Map(BTreeMap<CborValue, CborValue>),
    /// Represents a tagged value
    Tag(u64, Box<CborValue>),
    // The hidden variant allows the enum to be extended
    // with variants for tags and simple values.
    #[doc(hidden)]
    __Hidden,
}

impl CborValue {
    /// Returns true if the `CborValue` is an `Integer`. Returns false otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Integer(17.into());
    ///
    /// assert!(value.is_integer());
    /// ```
    pub fn is_integer(&self) -> bool {
        self.as_integer().is_some()
    }

    /// If the `CborValue` is a `Integer`, returns a reference to the associated `Integer` data.
    /// Returns None otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Integer(17.into());
    ///
    /// // We can read the number
    /// assert_eq!(17, value.as_integer().unwrap().try_into().unwrap());
    /// ```
    pub fn as_integer(&self) -> Option<i128> {
        match self {
            CborValue::Integer(int) => Some(*int),
            _ => None,
        }
    }

    /// If the `CborValue` is a `Integer`, returns a the associated `Integer` data as `Ok`.
    /// Returns `Err(Self)` otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Integer(17.into());
    /// assert_eq!(value.into_integer(), Ok(17));
    ///
    /// let value = CborValue::Bool(true);
    /// assert_eq!(value.into_integer(), Err(CborValue::Bool(true)));
    /// ```
    pub fn into_integer(self) -> Result<i128, Self> {
        match self {
            CborValue::Integer(int) => Ok(int),
            other => Err(other),
        }
    }

    /// Returns true if the `CborValue` is a `Bytes`. Returns false otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Bytes(vec![104, 101, 108, 108, 111]);
    ///
    /// assert!(value.is_bytes());
    /// ```
    pub fn is_bytes(&self) -> bool {
        self.as_bytes().is_some()
    }

    /// If the `CborValue` is a `Bytes`, returns a reference to the associated bytes vector.
    /// Returns None otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Bytes(vec![104, 101, 108, 108, 111]);
    ///
    /// assert_eq!(std::str::from_utf8(value.as_bytes().unwrap()).unwrap(), "hello");
    /// ```
    pub fn as_bytes(&self) -> Option<&Vec<u8>> {
        match *self {
            CborValue::Bytes(ref bytes) => Some(bytes),
            _ => None,
        }
    }

    /// If the `CborValue` is a `Bytes`, returns a mutable reference to the associated bytes vector.
    /// Returns None otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let mut value = CborValue::Bytes(vec![104, 101, 108, 108, 111]);
    /// value.as_bytes_mut().unwrap().clear();
    ///
    /// assert_eq!(value, CborValue::Bytes(vec![]));
    /// ```
    pub fn as_bytes_mut(&mut self) -> Option<&mut Vec<u8>> {
        match *self {
            CborValue::Bytes(ref mut bytes) => Some(bytes),
            _ => None,
        }
    }

    /// If the `CborValue` is a `Bytes`, returns a the associated `Vec<u8>` data as `Ok`.
    /// Returns `Err(Self)` otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Bytes(vec![104, 101, 108, 108, 111]);
    /// assert_eq!(value.into_bytes(), Ok(vec![104, 101, 108, 108, 111]));
    ///
    /// let value = CborValue::Bool(true);
    /// assert_eq!(value.into_bytes(), Err(CborValue::Bool(true)));
    /// ```
    pub fn into_bytes(self) -> Result<Vec<u8>, Self> {
        match self {
            CborValue::Bytes(vec) => Ok(vec),
            other => Err(other),
        }
    }

    /// Returns true if the `CborValue` is a `Float`. Returns false otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Float(17.0.into());
    ///
    /// assert!(value.is_float());
    /// ```
    pub fn is_float(&self) -> bool {
        self.as_float().is_some()
    }

    /// If the `CborValue` is a `Float`, returns a reference to the associated float data.
    /// Returns None otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Float(17.0.into());
    ///
    /// // We can read the float number
    /// assert_eq!(value.as_float().unwrap(), 17.0_f64);
    /// ```
    pub fn as_float(&self) -> Option<f64> {
        match *self {
            CborValue::Float(f) => Some(f),
            _ => None,
        }
    }

    /// If the `CborValue` is a `Float`, returns a the associated `f64` data as `Ok`.
    /// Returns `Err(Self)` otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Float(17.);
    /// assert_eq!(value.into_float(), Ok(17.));
    ///
    /// let value = CborValue::Bool(true);
    /// assert_eq!(value.into_float(), Err(CborValue::Bool(true)));
    /// ```
    pub fn into_float(self) -> Result<f64, Self> {
        match self {
            CborValue::Float(f) => Ok(f),
            other => Err(other),
        }
    }

    /// Returns true if the `CborValue` is a `Text`. Returns false otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Text(String::from("hello"));
    ///
    /// assert!(value.is_text());
    /// ```
    pub fn is_text(&self) -> bool {
        self.as_text().is_some()
    }

    /// If the `CborValue` is a `Text`, returns a reference to the associated `String` data.
    /// Returns None otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Text(String::from("hello"));
    ///
    /// // We can read the String
    /// assert_eq!(value.as_text().unwrap(), "hello");
    /// ```
    pub fn as_text(&self) -> Option<&str> {
        match *self {
            CborValue::Text(ref s) => Some(s),
            _ => None,
        }
    }

    /// If the `CborValue` is a `Text`, returns a mutable reference to the associated `String` data.
    /// Returns None otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let mut value = CborValue::Text(String::from("hello"));
    /// value.as_text_mut().unwrap().clear();
    ///
    /// assert_eq!(value.as_text().unwrap(), &String::from(""));
    /// ```
    pub fn as_text_mut(&mut self) -> Option<&mut String> {
        match *self {
            CborValue::Text(ref mut s) => Some(s),
            _ => None,
        }
    }

    /// If the `CborValue` is a `String`, returns a the associated `String` data as `Ok`.
    /// Returns `Err(Self)` otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Text(String::from("hello"));
    /// assert_eq!(value.into_text().as_deref(), Ok("hello"));
    ///
    /// let value = CborValue::Bool(true);
    /// assert_eq!(value.into_text(), Err(CborValue::Bool(true)));
    /// ```
    pub fn into_text(self) -> Result<String, Self> {
        match self {
            CborValue::Text(s) => Ok(s),
            other => Err(other),
        }
    }

    /// Returns true if the `CborValue` is a `Bool`. Returns false otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Bool(false);
    ///
    /// assert!(value.is_bool());
    /// ```
    pub fn is_bool(&self) -> bool {
        self.as_bool().is_some()
    }

    /// If the `CborValue` is a `Bool`, returns a copy of the associated boolean value. Returns None
    /// otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Bool(false);
    ///
    /// assert_eq!(value.as_bool().unwrap(), false);
    /// ```
    pub fn as_bool(&self) -> Option<bool> {
        match *self {
            CborValue::Bool(b) => Some(b),
            _ => None,
        }
    }

    /// If the `CborValue` is a `Bool`, returns a the associated `bool` data as `Ok`.
    /// Returns `Err(Self)` otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Bool(false);
    /// assert_eq!(value.into_bool(), Ok(false));
    ///
    /// let value = CborValue::Float(17.);
    /// assert_eq!(value.into_bool(), Err(CborValue::Float(17.)));
    /// ```
    pub fn into_bool(self) -> Result<bool, Self> {
        match self {
            CborValue::Bool(b) => Ok(b),
            other => Err(other),
        }
    }

    /// Returns true if the `CborValue` is a `Null`. Returns false otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Null;
    ///
    /// assert!(value.is_null());
    /// ```
    pub fn is_null(&self) -> bool {
        matches!(self, CborValue::Null)
    }

    /// Returns true if the `CborValue` is a `Tag`. Returns false otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Tag(61, Box::from(CborValue::Null));
    ///
    /// assert!(value.is_tag());
    /// ```
    pub fn is_tag(&self) -> bool {
        self.as_tag().is_some()
    }

    /// If the `CborValue` is a `Tag`, returns the associated tag value and a reference to the tag `CborValue`.
    /// Returns None otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Tag(61, Box::from(CborValue::Bytes(vec![104, 101, 108, 108, 111])));
    ///
    /// let (tag, data) = value.as_tag().unwrap();
    /// assert_eq!(tag, 61);
    /// assert_eq!(data, &CborValue::Bytes(vec![104, 101, 108, 108, 111]));
    /// ```
    pub fn as_tag(&self) -> Option<(u64, &CborValue)> {
        match self {
            CborValue::Tag(tag, data) => Some((*tag, data)),
            _ => None,
        }
    }

    /// If the `CborValue` is a `Tag`, returns the associated tag value and a mutable reference
    /// to the tag `CborValue`. Returns None otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let mut value = CborValue::Tag(61, Box::from(CborValue::Bytes(vec![104, 101, 108, 108, 111])));
    ///
    /// let (tag, mut data) = value.as_tag_mut().unwrap();
    /// data.as_bytes_mut().unwrap().clear();
    /// assert_eq!(tag, &61);
    /// assert_eq!(data, &CborValue::Bytes(vec![]));
    /// ```
    pub fn as_tag_mut(&mut self) -> Option<(&mut u64, &mut CborValue)> {
        match self {
            CborValue::Tag(tag, data) => Some((tag, data.as_mut())),
            _ => None,
        }
    }

    /// If the `CborValue` is a `Tag`, returns a the associated pair of `u64` and `Box<value>` data as `Ok`.
    /// Returns `Err(Self)` otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Tag(7, Box::new(CborValue::Float(12.)));
    /// assert_eq!(value.into_tag(), Ok((7, Box::new(CborValue::Float(12.)))));
    ///
    /// let value = CborValue::Bool(true);
    /// assert_eq!(value.into_tag(), Err(CborValue::Bool(true)));
    /// ```
    pub fn into_tag(self) -> Result<(u64, Box<CborValue>), Self> {
        match self {
            CborValue::Tag(tag, value) => Ok((tag, value)),
            other => Err(other),
        }
    }

    /// Returns true if the `CborValue` is an Array. Returns false otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Array(
    ///     vec![
    ///         CborValue::Text(String::from("foo")),
    ///         CborValue::Text(String::from("bar"))
    ///     ]
    /// );
    ///
    /// assert!(value.is_array());
    /// ```
    pub fn is_array(&self) -> bool {
        self.as_array().is_some()
    }

    /// If the `CborValue` is an Array, returns a reference to the associated vector. Returns None
    /// otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Array(
    ///     vec![
    ///         CborValue::Text(String::from("foo")),
    ///         CborValue::Text(String::from("bar"))
    ///     ]
    /// );
    ///
    /// // The length of `value` is 2 elements.
    /// assert_eq!(value.as_array().unwrap().len(), 2);
    /// ```
    pub fn as_array(&self) -> Option<&Vec<CborValue>> {
        match *self {
            CborValue::Array(ref array) => Some(array),
            _ => None,
        }
    }

    /// If the `CborValue` is an Array, returns a mutable reference to the associated vector.
    /// Returns None otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let mut value = CborValue::Array(
    ///     vec![
    ///         CborValue::Text(String::from("foo")),
    ///         CborValue::Text(String::from("bar"))
    ///     ]
    /// );
    ///
    /// value.as_array_mut().unwrap().clear();
    /// assert_eq!(value, CborValue::Array(vec![]));
    /// ```
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<CborValue>> {
        match *self {
            CborValue::Array(ref mut list) => Some(list),
            _ => None,
        }
    }

    /// If the `CborValue` is a `Array`, returns a the associated `Vec<CborValue>` data as `Ok`.
    /// Returns `Err(Self)` otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let mut value = CborValue::Array(
    ///     vec![
    ///         CborValue::Integer(17.into()),
    ///         CborValue::Float(18.),
    ///     ]
    /// );
    /// assert_eq!(value.into_array(), Ok(vec![CborValue::Integer(17.into()), CborValue::Float(18.)]));
    ///
    /// let value = CborValue::Bool(true);
    /// assert_eq!(value.into_array(), Err(CborValue::Bool(true)));
    /// ```
    pub fn into_array(self) -> Result<Vec<CborValue>, Self> {
        match self {
            CborValue::Array(vec) => Ok(vec),
            other => Err(other),
        }
    }

    /// Returns true if the `CborValue` is a Map. Returns false otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Map(
    ///     vec![
    ///         (CborValue::Text(String::from("foo")), CborValue::Text(String::from("bar")))
    ///     ].into_iter().collect()
    /// );
    ///
    /// assert!(value.is_map());
    /// ```
    pub fn is_map(&self) -> bool {
        self.as_map().is_some()
    }

    /// If the `CborValue` is a Map, returns a reference to the associated Map data. Returns None
    /// otherwise.
    ///
    /// ```
    /// # use isomdl::cbor::CborValue;
    /// #
    /// let value = CborValue::Map(
    ///     vec![
    ///         (CborValue::Text(String::from("foo")), CborValue::Text(String::from("bar")))
    ///     ].into_iter().collect()
    /// );
    ///
    /// // The length of data is 1 entry (1 key/value pair).
    /// assert_eq!(value.as_map().unwrap().len(), 1);
    ///
    /// // The content of the first element is what we expect
    /// assert_eq!(
    ///     value.as_map().unwrap().get(0.into()).unwrap(),
    ///     &(CborValue::Text(String::from("foo")), CborValue::Text(String::from("bar")))
    /// );
    /// ```
    pub fn as_map(&self) -> Option<&BTreeMap<CborValue, CborValue>> {
        match *self {
            CborValue::Map(ref map) => Some(map),
            _ => None,
        }
    }

    /// If the `CborValue` is a Map, returns a mutable reference to the associated Map Data.
    /// Returns None otherwise.
    ///
    /// ```
    /// # use std::collections::BTreeMap;
    /// use isomdl::cbor::CborValue;
    /// #
    /// let mut value = CborValue::Map(
    ///     vec![
    ///         (CborValue::Text(String::from("foo")), CborValue::Text(String::from("bar")))
    ///     ].into_iter().collect()
    /// );
    ///
    /// value.as_map_mut().unwrap().clear();
    /// assert_eq!(value, CborValue::Map(BTreeMap::new()));
    /// assert_eq!(value.as_map().unwrap().len(), 0);
    /// ```
    pub fn as_map_mut(&mut self) -> Option<&mut BTreeMap<CborValue, CborValue>> {
        match *self {
            CborValue::Map(ref mut map) => Some(map),
            _ => None,
        }
    }

    /// If the `CborValue` is a `Map`, returns a the associated `Vec<(CborValue, CborValue)>` data as `Ok`.
    /// Returns `Err(Self)` otherwise.
    ///
    /// ```
    /// # use std::collections::BTreeMap;
    /// use isomdl::cbor::CborValue;
    /// #
    /// let mut value = CborValue::Map(
    ///     vec![
    ///         (CborValue::Text(String::from("key")), CborValue::Float(18.)),
    ///     ].into_iter().collect()
    /// );
    /// assert_eq!(value.into_map(),
    ///     Ok(vec![
    ///         (CborValue::Text(String::from("key")), CborValue::Float(18.))
    ///             ]
    ///         .into_iter()
    ///         .collect::<BTreeMap<CborValue, CborValue>>()));
    ///
    /// let value = CborValue::Bool(true);
    /// assert_eq!(value.into_map(), Err(CborValue::Bool(true)));
    /// ```
    pub fn into_map(self) -> Result<BTreeMap<CborValue, CborValue>, Self> {
        match self {
            CborValue::Map(map) => Ok(map),
            other => Err(other),
        }
    }
}

fn cbor_value_into_ciborium_value(val: &CborValue) -> Value {
    match val {
        CborValue::Null => Value::Null,
        CborValue::Bool(b) => Value::Bool(*b),
        CborValue::Integer(i) => Value::Integer((*i).try_into().unwrap()),
        CborValue::Float(f) => Value::Float(*f),
        CborValue::Bytes(b) => Value::Bytes(b.clone()),
        CborValue::Text(t) => Value::Text(t.to_string()),
        CborValue::Array(a) => {
            Value::Array(a.into_iter().map(cbor_value_into_ciborium_value).collect())
        }
        CborValue::Map(m) => Value::Map(
            m.into_iter()
                .map(|(k, v)| {
                    (
                        cbor_value_into_ciborium_value(k),
                        cbor_value_into_ciborium_value(v),
                    )
                })
                .collect(),
        ),
        CborValue::Tag(t, v) => Value::Tag(*t, Box::new(cbor_value_into_ciborium_value(&*v))),
        _ => unimplemented!("Unsupported cbor value {val:?}"),
    }
}

fn ciborium_value_into_cbor_value(val: &Value) -> CborValue {
    match val {
        Value::Null => CborValue::Null,
        Value::Bool(b) => CborValue::Bool(*b),
        Value::Integer(i) => CborValue::Integer((*i).into()),
        Value::Float(f) => CborValue::Float(*f),
        Value::Bytes(b) => CborValue::Bytes(b.clone()),
        Value::Text(t) => CborValue::Text(t.to_string()),
        Value::Array(a) => {
            CborValue::Array(a.into_iter().map(ciborium_value_into_cbor_value).collect())
        }
        Value::Map(m) => CborValue::Map(
            m.into_iter()
                .map(|(k, v)| {
                    (
                        ciborium_value_into_cbor_value(k),
                        ciborium_value_into_cbor_value(v),
                    )
                })
                .collect(),
        ),
        Value::Tag(t, v) => CborValue::Tag(*t, Box::new(ciborium_value_into_cbor_value(&*v))),
        _ => unimplemented!("Unsupported cbor value {val:?}"),
    }
}

impl PartialEq for CborValue {
    fn eq(&self, other: &CborValue) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for CborValue {}

impl PartialOrd for CborValue {
    fn partial_cmp(&self, other: &CborValue) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CborValue {
    fn cmp(&self, other: &CborValue) -> Ordering {
        // Determine the canonical order of two values:
        // 1. Smaller major type sorts first.
        // 2. Shorter sequence sorts first.
        // 3. Compare integers by magnitude.
        // 4. Compare byte and text sequences lexically.
        // 5. Compare the serializations of both types. (expensive)
        use self::CborValue::*;
        if self.major_type() != other.major_type() {
            return self.major_type().cmp(&other.major_type());
        }
        match (self, other) {
            (Integer(a), Integer(b)) => a.abs().cmp(&b.abs()),
            (Bytes(a), Bytes(b)) if a.len() != b.len() => a.len().cmp(&b.len()),
            (Text(a), Text(b)) if a.len() != b.len() => a.len().cmp(&b.len()),
            (Array(a), Array(b)) if a.len() != b.len() => a.len().cmp(&b.len()),
            (Map(a), Map(b)) if a.len() != b.len() => a.len().cmp(&b.len()),
            (Bytes(a), Bytes(b)) => a.cmp(b),
            (Text(a), Text(b)) => a.cmp(b),
            (a, b) => a.cmp(&b),
        }
    }
}

macro_rules! impl_from {
    ($variant:path, $for_type:ty) => {
        impl From<$for_type> for CborValue {
            fn from(v: $for_type) -> CborValue {
                $variant(v.into())
            }
        }
    };
}

impl_from!(CborValue::Bool, bool);
impl_from!(CborValue::Integer, i8);
impl_from!(CborValue::Integer, i16);
impl_from!(CborValue::Integer, i32);
impl_from!(CborValue::Integer, i64);
// i128 omitted because not all numbers fit in CBOR serialization
impl_from!(CborValue::Integer, u8);
impl_from!(CborValue::Integer, u16);
impl_from!(CborValue::Integer, u32);
impl_from!(CborValue::Integer, u64);
// u128 omitted because not all numbers fit in CBOR serialization
impl_from!(CborValue::Float, f32);
impl_from!(CborValue::Float, f64);
impl_from!(CborValue::Bytes, Vec<u8>);
impl_from!(CborValue::Text, String);
impl_from!(CborValue::Array, Vec<CborValue>);
impl_from!(CborValue::Map, BTreeMap<CborValue, CborValue>);

impl CborValue {
    fn major_type(&self) -> u8 {
        use self::CborValue::*;
        match self {
            Null => 7,
            Bool(_) => 7,
            CborValue::Integer(v) => {
                if *v >= 0 {
                    0
                } else {
                    1
                }
            }
            Tag(_, _) => 6,
            Float(_) => 7,
            Bytes(_) => 2,
            Text(_) => 3,
            Array(_) => 4,
            Map(_) => 5,
            __Hidden => unreachable!(),
        }
    }
}

impl From<Value> for CborValue {
    fn from(value: Value) -> Self {
        ciborium_value_into_cbor_value(&value)
    }
}

impl Serialize for CborValue {
    fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        unimplemented!();
    }
}

impl<'de> Deserialize<'de> for CborValue {
    fn deserialize<D>(_d: D) -> Result<CborValue, D::Error>
    where
        D: Deserializer<'de>,
    {
        unimplemented!();
    }
}

impl From<CborValue> for Value {
    fn from(v: CborValue) -> Value {
        cbor_value_into_ciborium_value(&v)
    }
}

impl From<u128> for CborValue {
    #[inline]
    fn from(value: u128) -> Self {
        if let Ok(x) = Integer::try_from(value) {
            return CborValue::from(Value::Integer(x));
        }

        let mut bytes = &value.to_be_bytes()[..];
        while let Some(0) = bytes.first() {
            bytes = &bytes[1..];
        }

        CborValue::from(Value::Tag(BIGPOS, Value::Bytes(bytes.into()).into()))
    }
}

impl From<i128> for CborValue {
    #[inline]
    fn from(value: i128) -> Self {
        if let Ok(x) = Integer::try_from(value) {
            return CborValue::from(Value::Integer(x));
        }

        let (tag, raw) = match value.is_negative() {
            true => (BIGNEG, value as u128 ^ !0),
            false => (BIGPOS, value as u128),
        };

        let mut bytes = &raw.to_be_bytes()[..];
        while let Some(0) = bytes.first() {
            bytes = &bytes[1..];
        }

        CborValue::from(Value::Tag(tag, Value::Bytes(bytes.into()).into()))
    }
}

impl From<char> for CborValue {
    #[inline]
    fn from(value: char) -> Self {
        let mut v = String::with_capacity(1);
        v.push(value);
        CborValue::from(Value::Text(v))
    }
}

impl From<&String> for CborValue {
    #[inline]
    fn from(value: &String) -> Self {
        CborValue::from(Value::Text(value.to_string()))
    }
}

impl From<&str> for CborValue {
    #[inline]
    fn from(value: &str) -> Self {
        CborValue::from(Value::Text(value.to_string()))
    }
}

impl From<&Vec<u8>> for CborValue {
    #[inline]
    fn from(value: &Vec<u8>) -> Self {
        CborValue::from(Value::Bytes(value.to_vec()))
    }
}

impl From<&Value> for CborValue {
    #[inline]
    fn from(value: &Value) -> Self {
        CborValue::from(value.clone())
    }
}

impl From<&CborValue> for Value {
    #[inline]
    fn from(value: &CborValue) -> Self {
        cbor_value_into_ciborium_value(value)
    }
}

impl From<&CborValue> for CborValue {
    #[inline]
    fn from(value: &CborValue) -> Self {
        value.clone()
    }
}

impl TryFrom<CborValue> for u8 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not u8"))
    }
}

impl TryFrom<CborValue> for i8 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not i8"))
    }
}

impl TryFrom<CborValue> for u16 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not u16"))
    }
}

impl TryFrom<CborValue> for i16 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not i16"))
    }
}

impl TryFrom<CborValue> for u32 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not u32"))
    }
}

impl TryFrom<CborValue> for i32 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not i32"))
    }
}

impl TryFrom<CborValue> for u64 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not u64"))
    }
}

impl TryFrom<CborValue> for i64 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not i64"))
    }
}

impl TryFrom<CborValue> for u128 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not u128"))
    }
}

impl TryFrom<CborValue> for i128 {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_integer()
            .map_err(|_| Error::Deserialize("not an integer"))?
            .try_into()
            .map_err(|_| Error::Deserialize("not i128"))
    }
}

impl TryFrom<CborValue> for bool {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_bool()
            .map_err(|_| Error::Deserialize("not a bool"))
    }
}

impl TryFrom<CborValue> for String {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_text()
            .map_err(|_| Error::Deserialize("not a string"))
    }
}

impl TryFrom<CborValue> for Vec<u8> {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_bytes()
            .map_err(|_| Error::Deserialize("not bytes"))
    }
}

impl TryFrom<CborValue> for BTreeMap<CborValue, CborValue> {
    type Error = Error;

    fn try_from(value: CborValue) -> Result<Self, Self::Error> {
        value
            .into_map()
            .map_err(|_| Error::Deserialize("not bytes"))
    }
}

impl CborSerializable for CborValue {}
impl AsCborValue for CborValue {
    fn from_cbor_value(value: Value) -> coset::Result<Self> {
        Ok(value.into())
    }

    fn to_cbor_value(self) -> coset::Result<Value> {
        Ok(self.into())
    }
}
