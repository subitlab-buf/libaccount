use std::{collections::HashSet, hash::Hash};

use serde_repr::{Deserialize_repr, Serialize_repr};

/// An account containing basic information and permissions.
pub struct Account<P> {
    perms: Permissions<P>,
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
    /// Gets academy the house belongs to.
    ///
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
