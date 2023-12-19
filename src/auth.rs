use std::{borrow::Cow, collections::HashMap, time::Duration};

use sha256::Sha256Digest;
use time::OffsetDateTime;

/// A type storing tokens for an account.
///
/// See [`Token`].
#[derive(Debug, Default)]
pub struct Tokens {
    /// Token sha256 -> Expired timestamp.
    inner: HashMap<String, Option<OffsetDateTime>>,
}

impl Tokens {
    /// Creates a new default tokens.
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    /// Gets a [`Token`] from given raw token.
    pub fn get<T>(&self, token: T) -> Option<Token<'_>>
    where
        T: Sha256Digest,
    {
        let digest = sha256::digest(token);
        self.inner.get_key_value(&digest).map(|(sha, exp)| Token {
            sha: Cow::Borrowed(sha),
            expired: *exp,
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
    pub fn put(&mut self, token: Token<'static>) {
        let now = OffsetDateTime::now_utc();
        self.inner.retain(|_, e| e.map_or(true, |e| now < e));
        self.inner.insert(token.sha.into_owned(), token.expired);
    }

    /// Revokes the given token and returns whether the
    /// token was successfully revoked.
    pub fn revoke<T>(&mut self, token: T) -> bool
    where
        T: Sha256Digest,
    {
        let digest = sha256::digest(token);
        self.inner.remove(&digest).is_some()
    }
}

/// A token.
pub struct Token<'a> {
    /// Token sha256 value.
    sha: Cow<'a, str>,
    /// Expired timestamp.
    expired: Option<OffsetDateTime>,
}

impl Token<'_> {
    /// Returns the sha256-digested token.
    pub fn digested(&self) -> &str {
        &self.sha
    }

    /// Whether this token is not expired.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.expired.map_or(true, |e| OffsetDateTime::now_utc() < e)
    }
}

impl Token<'static> {
    /// Creates a new digested token with given
    /// expire duration and returns the raw token.
    pub fn new(expire_duration: Option<Duration>) -> (Self, String) {
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
