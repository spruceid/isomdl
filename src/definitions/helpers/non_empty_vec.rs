use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(try_from = "Vec<T>", into = "Vec<T>")]
pub struct NonEmptyVec<T: Clone>(Vec<T>);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot construct a non-empty vec from an empty vec")]
    Empty,
}

impl<T: Clone> NonEmptyVec<T> {
    pub fn new(t: T) -> Self {
        Self(vec![t])
    }

    pub fn first(&self) -> &T {
        // Will not panic as NonEmptyVec has at least one element by construction.
        &self[0]
    }

    pub fn push(&mut self, t: T) {
        self.0.push(t)
    }
}

impl<T: Clone> TryFrom<Vec<T>> for NonEmptyVec<T> {
    type Error = Error;

    fn try_from(v: Vec<T>) -> Result<NonEmptyVec<T>, Error> {
        if v.is_empty() {
            return Err(Error::Empty);
        }
        Ok(NonEmptyVec(v))
    }
}

impl<T: Clone> From<NonEmptyVec<T>> for Vec<T> {
    fn from(NonEmptyVec(v): NonEmptyVec<T>) -> Vec<T> {
        v
    }
}

impl<T: Clone> AsRef<[T]> for NonEmptyVec<T> {
    fn as_ref(&self) -> &[T] {
        &self.0
    }
}

impl<T: Clone> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}
