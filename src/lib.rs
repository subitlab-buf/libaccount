use std::{
    collections::HashSet,
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    num::NonZeroU64,
    time::Duration,
};

use auth::{DigestedPassword, DigestedToken, Token, Tokens};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

/// Passwords and tokens.
pub mod auth;
pub mod tag;

pub use sha256;
use tag::{Tag, Tags};

/// A verified account,
/// containing basic information and permissions.
///
/// # Serialization and deserialization
///
/// The `id` field will be skipped.
/// See [`Self::initialize_id`].
#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "T: Serialize, E: Serialize",
    deserialize = "T: Eq + Hash + Deserialize<'de>, E: Deserialize<'de>, <T as Tag>::Entry: Eq + Hash"
))]
pub struct Account<T: Tag, E = ()> {
    /// The unique identifier of this account,
    /// as a number.
    #[serde(skip)]
    id: u64,
    /// The unique identifier of this account,
    /// as an email address.
    email: String,

    /// Full real name of the user.
    name: String,

    /// The school ID of the user.
    school_id: String,
    /// The phone of the user.
    phone: Option<Phone>,

    /// External data of this account.
    ext: E,
    tags: Tags<<T as Tag>::Entry, T>,

    /// Password digested by sha256.
    password_sha: DigestedPassword,

    /// Seconds tokens will expire.\
    /// Zero stands for never expire.
    token_expire_time: u64,
    tokens: Tokens,
}

impl<T: Tag + std::fmt::Debug, E: std::fmt::Debug> std::fmt::Debug for Account<T, E>
where
    <T as Tag>::Entry: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("name", &self.name)
            .field("school_id", &self.school_id)
            .field("phone", &self.phone)
            .field("ext", &self.ext)
            .field("tags", &self.tags)
            .field("token_expire_time", &self.token_expire_time)
            .field("tokens", &self.tokens)
            .finish()
    }
}

impl<T: Tag, E> Account<T, E> {
    /// Unique identifier of this account.
    #[inline]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Sets the identifier of this account.
    ///
    /// # Safety
    ///
    /// This will cause unexpected result if the id
    /// was initialized.
    /// Use this when you have to change the id.
    #[inline]
    pub unsafe fn initialize_id(&mut self, id: u64) {
        self.id = id;
    }

    /// Email address of this account.
    #[inline]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Real name of this account.
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Sets the real name of this account.
    #[inline]
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// School ID of this account.
    #[inline]
    pub fn school_id(&self) -> &str {
        &self.school_id
    }

    /// Sets the school ID of this account.
    #[inline]
    pub fn set_school_id(&mut self, sid: String) {
        self.school_id = sid;
    }

    /// Phone of this account.
    #[inline]
    pub fn phone(&self) -> Option<Phone> {
        self.phone
    }

    /// Sets the phone of this account.
    #[inline]
    pub fn set_phone(&mut self, phone: Phone) {
        self.phone = Some(phone);
    }

    /// External data of this account.
    #[inline]
    pub fn ext(&self) -> &E {
        &self.ext
    }

    /// Mutable external data of this account.
    #[inline]
    pub fn ext_mut(&mut self) -> &mut E {
        &mut self.ext
    }

    /// Gets tags of this account.
    #[inline]
    pub fn tags(&self) -> &Tags<<T as Tag>::Entry, T> {
        &self.tags
    }

    /// Gets mutbale tags of this account.
    #[inline]
    pub fn tags_mut(&mut self) -> &mut Tags<<T as Tag>::Entry, T> {
        &mut self.tags
    }

    /// Seconds token will expire.
    #[inline]
    pub fn token_expire_time(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.token_expire_time)
    }

    /// Sets the time token will expire.
    #[inline]
    pub fn set_token_expire_time(&mut self, time: Option<u64>) {
        self.token_expire_time = time.unwrap_or(0);
    }

    /// Sets the password of this account.
    #[inline]
    pub fn set_password<P>(&mut self, password: P)
    where
        P: AsRef<str>,
    {
        self.password_sha = password.into();
    }

    #[inline]
    pub fn is_token_valid<S>(&self, token: S) -> bool
    where
        S: AsRef<str>,
    {
        self.tokens.is_valid(token.as_ref())
    }

    #[inline]
    pub fn password_matches(&self, password: &str) -> bool {
        self.password_sha.matches(password)
    }
}

/// An unverified account.
#[derive(Debug, Serialize, Deserialize)]
pub struct Unverified<E> {
    #[serde(skip)]
    email_hash: u64,
    email: String,
    ext: E,
}

impl<E> Unverified<E> {
    #[inline]
    pub fn email_hash(&self) -> u64 {
        self.email_hash
    }

    #[inline]
    pub unsafe fn initialize_email_hash(&mut self, hash: u64) {
        self.email_hash = hash;
    }

    /// Email address of this account.
    #[inline]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// External data of this account.
    #[inline]
    pub fn ext(&self) -> &E {
        &self.ext
    }

    /// Mutable external data of this account.
    #[inline]
    pub fn ext_mut(&mut self) -> &mut E {
        &mut self.ext
    }
}

#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "T: Serialize, Args: Serialize",
    deserialize = "T: Eq + Hash + Deserialize<'de>, Args: Deserialize<'de>, <T as Tag>::Entry: Eq + Hash"
))]
pub struct VerifyDescriptor<T: Tag, Args> {
    pub email: String,
    /// Full real name of the user.
    pub name: String,
    /// The school ID of the user.
    pub school_id: String,
    /// The phone of the user.
    pub phone: Option<Phone>,

    /// The password.
    pub password: String,

    #[serde(flatten)]
    pub ext_args: Args,
    #[serde(default)]
    pub tags: Tags<<T as Tag>::Entry, T>,
}

/// Types that can process verification request,
/// stored in [`Unverified`].
///
/// # Generic Parameters
///
/// - `E`: The external data type in a verified
/// account. See [`Account`].
pub trait ExtVerify<T: Tag, E> {
    type Args;
    type Error;

    /// Into the external data type from given discriptor,
    /// or else throw an error.
    fn into_verified_ext(
        self,
        args: &mut VerifyDescriptor<T, Self::Args>,
    ) -> Result<E, Self::Error>;
}

impl<E> Unverified<E> {
    /// Creates a new unverified account from given
    /// email address.
    pub fn new<H>(email: String, ext: E, mut hasher: H) -> Result<Self, Error>
    where
        H: Hasher,
    {
        const LEGAL_SUFFIXES: [&str; 2] = ["@pkuschool.edu.cn", "@i.pkuschool.edu.cn"];

        if !LEGAL_SUFFIXES.into_iter().any(|suf| email.ends_with(suf)) {
            return Err(Error::InvalidPKUSEmailAddress);
        }

        email.hash(&mut hasher);
        Ok(Self {
            email_hash: hasher.finish(),
            email,
            ext,
        })
    }

    /// Verify this account to a verified account.
    pub fn verify<T: Tag, E1>(
        self,
        mut descriptor: VerifyDescriptor<T, <E as ExtVerify<T, E1>>::Args>,
    ) -> Result<Account<T, E1>, <E as ExtVerify<T, E1>>::Error>
    where
        E: ExtVerify<T, E1>,
    {
        assert_eq!(self.email, descriptor.email);
        let id = self.email_hash;
        let ext = self.ext.into_verified_ext(&mut descriptor)?;

        Ok(Account {
            id,
            email: descriptor.email,
            name: descriptor.name,
            school_id: descriptor.school_id,
            phone: descriptor.phone,
            ext,
            tags: descriptor.tags,
            password_sha: descriptor.password.into(),
            token_expire_time: time::Duration::WEEK.whole_seconds() as u64,
            tokens: Tokens::new(),
        })
    }
}

impl<T: Tag, E> Account<T, E> {
    /// Logins into this account with given raw password.
    pub fn login(&mut self, password: &str) -> Result<(Token, Option<i64>), Error> {
        if self.password_sha.matches(password) {
            let (digested, token) = DigestedToken::new(
                self.token_expire_time()
                    .map(|n| Duration::from_secs(n.get())),
            );
            let t = digested.expired_timestamp();
            self.tokens.put(digested);
            Ok((token, t))
        } else {
            Err(Error::PasswordIncorrect)
        }
    }

    /// Logout from this account and revokes given token.
    pub fn logout(&mut self, token: &str) -> Result<(), Error> {
        if self.tokens.revoke(token) {
            Ok(())
        } else {
            Err(Error::InvalidToken)
        }
    }
}

/// Variant of a user.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum UserType {
    Student,
    Teacher,
}

/// Represents a phone number and its region.
///
/// # Deserialization
///
/// This type could be deserialized from either
/// a +86 phone number or a struct.
#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
pub struct Phone {
    region: u16,
    number: u64,
}

impl Phone {
    /// Creates a new phone number with the given
    /// region and number.
    #[inline]
    pub fn new(region: u16, number: u64) -> Self {
        Self { region, number }
    }

    const DEFUALT_REGION: u16 = 86;

    /// Gets the region of this phone number.
    #[inline]
    pub fn region(self) -> u16 {
        self.region
    }

    /// Gets the number of this phone number.
    #[inline]
    pub fn number(self) -> u64 {
        self.number
    }
}

impl From<u64> for Phone {
    #[inline]
    fn from(number: u64) -> Self {
        Self {
            region: Self::DEFUALT_REGION,
            number,
        }
    }
}

impl Display for Phone {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "+{} {}", self.region, self.number)
    }
}

impl<'de> Deserialize<'de> for Phone {
    #[inline]
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PVisitor;
        impl<'d> serde::de::Visitor<'d> for PVisitor {
            type Value = Phone;

            #[inline]
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a +86 phone number or struct Phone")
            }

            #[inline]
            fn visit_u64<E>(self, v: u64) -> std::prelude::v1::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v.into())
            }

            fn visit_seq<A>(self, mut seq: A) -> std::prelude::v1::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'d>,
            {
                let region = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let number = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                Ok(Phone { region, number })
            }

            fn visit_map<A>(self, mut map: A) -> std::prelude::v1::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'d>,
            {
                #[derive(Deserialize)]
                #[serde(field_identifier, rename_all = "lowercase")]
                enum Field {
                    Region,
                    Number,
                }

                let mut region = None;
                let mut number = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Region => {
                            if region.is_some() {
                                return Err(serde::de::Error::duplicate_field("region"));
                            }
                            region = Some(map.next_value()?);
                        }
                        Field::Number => {
                            if number.is_some() {
                                return Err(serde::de::Error::duplicate_field("number"));
                            }
                            number = Some(map.next_value()?);
                        }
                    }
                }
                let region = region.ok_or_else(|| serde::de::Error::missing_field("region"))?;
                let number = number.ok_or_else(|| serde::de::Error::missing_field("number"))?;
                Ok(Phone { region, number })
            }
        }

        deserializer.deserialize_any(PVisitor)
    }
}

/// Represents houses of PKUSchool.
///
/// # Serialization
///
/// This type is serialized an deserialized as a number.
/// The number represents identifier of the house.
///
/// # References
///
/// [PKUSchool Yuque](https://pkuschool.yuque.com/infodesk/sbook/gwrsseb99rf0uv5y).
#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum House {
    GeWu = 1,
    ZhiZhi = 2,
    ChengYi = 3,
    ZhengXin = 4,
    MingDe = 5,
    ZhiShan = 6,
    XinMin = 7,
    XiJing = 8,
    HongYi = 9,
}

/// Represents academies of PKUSchool.
///
/// # Serialization
///
/// This type is serialized an deserialized as a number.
#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Academy {
    XingZhi = 1,
    Yuanpei = 2,
    Weiming = 3,
    Dalton = 4,
    Boya = 5,
    ShuRen = 6,
}

impl From<House> for Academy {
    /// Gets academy the house belongs to.\
    /// See [PKUSchool Yuque](https://pkuschool.yuque.com/infodesk/sbook/kg33nght6tn5f70x).
    #[inline]
    fn from(value: House) -> Self {
        match value {
            House::GeWu | House::ZhiZhi | House::ChengYi | House::ZhengXin => Academy::XingZhi,
            House::MingDe | House::HongYi => Academy::Yuanpei,
            House::ZhiShan | House::XinMin => Academy::Dalton,
            House::XiJing => Academy::Weiming,
        }
    }
}

/// An abstraction to permission group of accounts.
pub trait Permission: Sized {
    /// The default permission groups of an account.
    fn default_set() -> HashSet<Self>;

    /// Whether permission of the given permission group
    /// is contained by this permission group.
    fn contains(&self, permission: &Self) -> bool;
}

/// Error produced by this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("password incorrect")]
    PasswordIncorrect,
    #[error("invalid token")]
    InvalidToken,
    #[error("email address is not suffixed with @i.pkuschool.edu.cn or @pkuschool.edu.cn")]
    InvalidPKUSEmailAddress,
}
