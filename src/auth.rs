use std::{borrow::Cow, collections::HashMap};

pub struct Tokens {
    /// Token sha256 -> Expired timestamp.
    inner: HashMap<String, Option<u64>>,
}

impl Tokens {}

pub struct Token<'a> {
    /// Token sha256 value.
    token: Cow<'a, str>,
    /// Expired timestamp.
    expired: Option<u64>,
}

impl Token<'_> {}
