use std::{borrow::Cow, collections::HashMap, time::Duration};

use serde::{Deserialize, Serialize};
use sha256::Sha256Digest;
use time::OffsetDateTime;

/// A type storing tokens for an account.
///
/// See [`Token`].
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Tokens {
    /// Token sha256 -> Expired timestamp.
    inner: HashMap<String, Option<TimestampDateTime>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
struct TimestampDateTime(#[serde(with = "time::serde::timestamp")] OffsetDateTime);

impl Tokens {
    /// Creates a new default tokens.
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    /// Gets a [`Token`] from given raw token.
    pub fn get<T>(&self, token: T) -> Option<DigestedToken<'_>>
    where
        T: Sha256Digest,
    {
        let digest = sha256::digest(token);
        self.inner
            .get_key_value(&digest)
            .map(|(sha, exp)| DigestedToken {
                sha: Cow::Borrowed(sha),
                expired: exp.map(|e| e.0),
            })
    }

    /// Whether the given token is valid in
    /// this instance.
    #[inline]
    pub fn is_valid<T>(&self, token: T) -> bool
    where
        T: Sha256Digest,
    {
        self.get(token).map_or(false, |t| t.is_valid())
    }

    /// Puts a new token into this instance.
    pub fn put(&mut self, token: DigestedToken<'static>) {
        let now = OffsetDateTime::now_utc();
        self.inner.retain(|_, e| e.map_or(true, |e| now < e.0));
        self.inner
            .insert(token.sha.into_owned(), token.expired.map(TimestampDateTime));
    }

    /// Revokes the given token and returns whether the
    /// token was successfully revoked.
    pub fn revoke<T>(&mut self, token: T) -> bool
    where
        T: Sha256Digest,
    {
        let now = OffsetDateTime::now_utc();
        self.inner.retain(|_, e| e.map_or(true, |e| now < e.0));
        let digest = sha256::digest(token);
        self.inner.remove(&digest).is_some()
    }
}

/// A sha256-digested token.
pub struct DigestedToken<'a> {
    /// Token sha256 value.
    sha: Cow<'a, str>,
    /// Expired timestamp.
    expired: Option<OffsetDateTime>,
}

impl DigestedToken<'_> {
    /// Returns the sha256-digested token.
    pub fn digested(&self) -> &str {
        &self.sha
    }

    /// Whether this token is not expired.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.expired.map_or(true, |e| OffsetDateTime::now_utc() < e)
    }

    #[inline]
    pub fn expired_timestamp(&self) -> Option<i64> {
        self.expired.map(|t| t.unix_timestamp())
    }
}

impl DigestedToken<'static> {
    /// Creates a new digested token with given
    /// expire duration and returns the raw token.
    pub fn new(expire_duration: Option<Duration>) -> (Self, Token) {
        let token = rand::random::<[u8; 8]>()
            .map(|num| num.to_string())
            .join("-");

        (
            Self {
                sha: Cow::Owned(sha256::digest(&token)),
                expired: expire_duration.map(|i| OffsetDateTime::now_utc() + i),
            },
            token,
        )
    }
}

pub type Token = String;

/// A sha256-digested password.
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct DigestedPassword(String);

impl DigestedPassword {
    /// Whether the given password matches this
    /// digested password.
    #[inline]
    pub fn matches(&self, password: &str) -> bool {
        sha256::digest(password) == self.0
    }
}

impl<T> From<T> for DigestedPassword
where
    T: AsRef<str>,
{
    /// Digests a password.
    #[inline]
    fn from(value: T) -> Self {
        Self(sha256::digest(value.as_ref()))
    }
}
