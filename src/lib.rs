use core::fmt;
use std::{collections::HashSet, fmt::Display, hash::Hash};

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

pub mod auth;

/// An account containing basic information and permissions.
pub struct Account<P, E = ()> {
    /// The unique identifier of this account,
    /// as a number.
    id: u64,
    /// The unique identifier of this account,
    /// as an email address.
    email: String,

    /// Full real name of the user.
    name: String,
    /// The type of this account.
    variant: UserType,

    /// The house the user belongs to.\
    /// For both students and teachers.
    house: Option<House>,
    /// The academy the user belongs to.\
    /// For both students and teachers.
    academy: Option<Academy>,

    /// The school ID of the user.\
    /// For both students and teachers.
    school_id: String,
    /// The phone of the user.
    phone: Option<u64>,

    /// External data of this account.
    ext: E,
    /// Permissions of this account.
    perms: Permissions<P>,

    /// Password digested by `sha256`.
    password: String,
    /// Whether this account is verified.
    verified: bool,
}

impl<P, E> Account<P, E> {
    /// Unique identifier of this account.
    #[inline]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Email address of this account.
    #[inline]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// House this account belongs to.
    #[inline]
    pub fn house(&self) -> Option<House> {
        self.house
    }

    /// Sets the house this account belongs to.
    #[inline]
    pub fn set_house(&mut self, house: Option<House>) {
        self.house = house;
    }

    /// Academy this account belongs to.
    #[inline]
    pub fn academy(&self) -> Option<Academy> {
        self.academy.or(self.house.map(Academy::from))
    }

    /// Sets the academy this account belongs to.
    #[inline]
    pub fn set_academy(&mut self, academy: Option<Academy>) {
        self.academy = academy;
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
    pub fn set_school_id(&mut self, sid: String) -> Result<()> {
        // Validate student id.
        if self.variant == UserType::Student {
            if let Ok(_) = sid.parse::<u32>() {
                return Err(Error::InvalidStudentId(sid));
            }
        }
        self.school_id = sid;
        Ok(())
    }

    /// Phone of this account.
    #[inline]
    pub fn phone(&self) -> Option<u64> {
        self.phone
    }

    /// Sets the phone of this account.
    #[inline]
    pub fn set_phone(&mut self, phone: u64) {
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

    /// Type of this account.
    #[inline]
    pub fn variant(&self) -> UserType {
        self.variant
    }

    /// Sets the type of this account.
    #[inline]
    pub fn set_variant(&mut self, variant: UserType) {
        self.variant = variant;
    }

    /// Gets permissions of this account.
    #[inline]
    pub fn permissions(&self) -> &Permissions<P> {
        &self.perms
    }

    /// Gets mutable permissions of this account.
    #[inline]
    pub fn permissions_mut(&mut self) -> &mut Permissions<P> {
        &mut self.perms
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum UserType {
    Student,
    Teacher,
    /// A user who is neither student nor a teacher.
    Temp,
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn default_set() -> Permissions<Self>;

    /// Whether permission of the given permission group
    /// is contained by this permission group.
    fn contains(&self, permission: &Self) -> bool;
}

/// Permission groups of an account.
pub struct Permissions<P> {
    inner: HashSet<P>,
}

impl<P> Permissions<P> {
    /// Creates an empty permissions.
    #[inline]
    pub fn empty() -> Self {
        Self {
            inner: HashSet::new(),
        }
    }
}

impl<P> Permissions<P>
where
    P: Eq + Hash,
{
    /// Adds a permission group to this permissions
    /// and returns if the given permission group
    /// is already be contained by this permissions.
    #[inline]
    pub fn add(&mut self, permission: P) -> bool {
        self.inner.insert(permission)
    }

    /// Removes the given permission group from this
    /// permissions and returns
    #[inline]
    pub fn remove(&mut self, permission: &P) -> bool {
        self.inner.remove(permission)
    }
}

impl<P> Permissions<P>
where
    P: Eq + Hash + Permission,
{
    /// Returns whether this permissions contains the given
    /// permission group, or a permission group contains
    /// permission of the given group exists.
    #[inline]
    pub fn contains(&self, permission: &P) -> bool {
        self.inner.contains(permission) || self.inner.iter().any(|p| p.contains(permission))
    }
}

impl<P> Default for Permissions<P>
where
    P: Permission,
{
    /// Creates a permissions with the default
    /// set of the permission.
    #[inline]
    fn default() -> Self {
        P::default_set()
    }
}

impl<P: Serialize> Serialize for Permissions<P> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner.serialize(serializer)
    }
}

impl<'de, P: Deserialize<'de> + Hash + Eq> Deserialize<'de> for Permissions<P> {
    #[inline]
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = HashSet::deserialize(deserializer)?;
        Ok(Self { inner })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid student id {0}")]
    InvalidStudentId(String),
    #[error("invalid phone number {0}")]
    InvalidPhone(Phone),
}

pub type Result<T> = core::result::Result<T, Error>;
