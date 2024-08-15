use crate::definitions::helpers::{ByteStr, NonEmptyVec};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub trait FromJson: Sized {
    fn from_json(v: &Value) -> Result<Self, FromJsonError>;
    fn from_json_opt(o: Option<&Value>) -> Result<Self, FromJsonError> {
        o.ok_or(FromJsonError::Missing).and_then(Self::from_json)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FromJsonError {
    #[error("expected a positive integer")]
    ExpectedPositiveInteger,
    #[error("supplied integer exceeds maximum value")]
    IntegerTooLarge,
    #[error("multiple errors: {0:?}")]
    Multiple(Vec<FromJsonError>),
    #[error("field not found")]
    Missing,
    #[error(transparent)]
    Parsing(#[from] anyhow::Error),
    #[error("expected '{1}', received '{0}'")]
    UnexpectedType(&'static str, &'static str),
    #[error("{0}: {1}")]
    WithContext(&'static str, Box<FromJsonError>),
}

pub trait FromJsonMap: Sized {
    fn from_map(m: &Map<String, Value>) -> Result<Self, FromJsonError>;
}

impl FromJson for bool {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        match v {
            Value::Bool(b) => Ok(*b),
            Value::Null => Err(FromJsonError::UnexpectedType("null", "boolean")),
            Value::Number(_) => Err(FromJsonError::UnexpectedType("number", "boolean")),
            Value::String(_) => Err(FromJsonError::UnexpectedType("string", "boolean")),
            Value::Array(_) => Err(FromJsonError::UnexpectedType("array", "boolean")),
            Value::Object(_) => Err(FromJsonError::UnexpectedType("object", "boolean")),
        }
    }
}

impl FromJson for u32 {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        match v {
            Value::Number(n) => n
                .as_u64()
                .ok_or(FromJsonError::ExpectedPositiveInteger)?
                .try_into()
                .map_err(|_| FromJsonError::IntegerTooLarge),
            Value::Null => Err(FromJsonError::UnexpectedType("null", "number")),
            Value::Bool(_) => Err(FromJsonError::UnexpectedType("boolean", "number")),
            Value::String(_) => Err(FromJsonError::UnexpectedType("string", "number")),
            Value::Array(_) => Err(FromJsonError::UnexpectedType("array", "number")),
            Value::Object(_) => Err(FromJsonError::UnexpectedType("object", "number")),
        }
    }
}

impl FromJson for String {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        match v {
            Value::String(s) => Ok(s.clone()),
            Value::Null => Err(FromJsonError::UnexpectedType("null", "string")),
            Value::Bool(_) => Err(FromJsonError::UnexpectedType("boolean", "string")),
            Value::Number(_) => Err(FromJsonError::UnexpectedType("number", "string")),
            Value::Array(_) => Err(FromJsonError::UnexpectedType("array", "string")),
            Value::Object(_) => Err(FromJsonError::UnexpectedType("object", "string")),
        }
    }
}

impl<T> FromJson for Vec<T>
where
    T: FromJson,
{
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        match v {
            Value::Array(v) => v.iter().map(T::from_json).collect(),
            Value::Null => Err(FromJsonError::UnexpectedType("null", "array")),
            Value::Bool(_) => Err(FromJsonError::UnexpectedType("boolean", "array")),
            Value::Number(_) => Err(FromJsonError::UnexpectedType("number", "array")),
            Value::String(_) => Err(FromJsonError::UnexpectedType("string", "array")),
            Value::Object(_) => Err(FromJsonError::UnexpectedType("object", "array")),
        }
    }
}

impl<T> FromJson for NonEmptyVec<T>
where
    T: FromJson + Clone,
{
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        Vec::from_json(v).and_then(|v| {
            v.try_into()
                .map_err(Into::into)
                .map_err(FromJsonError::Parsing)
        })
    }
}

impl FromJson for ByteStr {
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        let encoded = String::from_json(v)?;
        base64::decode(encoded)
            .map(Into::into)
            .map_err(Into::into)
            .map_err(FromJsonError::Parsing)
    }
}

impl<T> FromJson for BTreeMap<String, T>
where
    T: FromJson,
{
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        match v {
            Value::Object(m) => Self::from_map(m),
            Value::Null => Err(FromJsonError::UnexpectedType("null", "object")),
            Value::Bool(_) => Err(FromJsonError::UnexpectedType("boolean", "object")),
            Value::Number(_) => Err(FromJsonError::UnexpectedType("number", "object")),
            Value::String(_) => Err(FromJsonError::UnexpectedType("string", "object")),
            Value::Array(_) => Err(FromJsonError::UnexpectedType("array", "object")),
        }
    }
}

impl<T> FromJsonMap for BTreeMap<String, T>
where
    T: FromJson,
{
    fn from_map(m: &Map<String, Value>) -> Result<Self, FromJsonError> {
        m.iter()
            .map(|(k, v)| Ok((k.clone(), T::from_json(v)?)))
            .collect()
    }
}

impl<T> FromJsonMap for Option<T>
where
    T: FromJsonMap,
{
    fn from_map(v: &Map<String, Value>) -> Result<Self, FromJsonError> {
        match T::from_map(v) {
            Ok(t) => Ok(Some(t)),
            Err(FromJsonError::Missing) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl<T> FromJson for Option<T>
where
    T: FromJson,
{
    fn from_json(v: &Value) -> Result<Self, FromJsonError> {
        if let &Value::Null = v {
            return Ok(None);
        }
        T::from_json(v).map(Some)
    }

    fn from_json_opt(o: Option<&Value>) -> Result<Self, FromJsonError> {
        if let Some(&Value::Null) = o {
            return Ok(None);
        }
        o.map(T::from_json).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macros::FromJson;
    use serde_json::{json, Value};

    #[derive(FromJson)]
    #[isomdl(crate = "crate")]
    struct S {
        a: Option<u32>,
    }

    #[test]
    fn null_as_none() {
        let v: Value = json!({ "a": null });
        let s = S::from_json(&v).unwrap();

        assert!(s.a.is_none());
    }

    #[test]
    fn int_as_some() {
        let v: Value = json!({ "a": 11 });
        let s = S::from_json(&v).unwrap();

        assert!(s.a.is_some());
    }
}
