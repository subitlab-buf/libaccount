use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use serde::{ser::SerializeSeq, Deserialize, Serialize};

use crate::Permission;

/// A collection of tags.
///
/// # Serialization and Deserialization
///
/// This type will be serialized and deserialized as a
/// sequence of tags (type `T`).
#[derive(Debug)]
pub struct Tags<E, T> {
    entries: HashMap<E, HashSet<T>>,
}

impl<E, T> Tags<E, T> {
    /// Creates a new tags storage.
    #[inline]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl<E: UserDefinableEntry, T> Tags<E, T> {
    /// Strips all non-user-definable entries form this
    /// tags storage.
    ///
    /// See [`UserDefinableEntry`].
    #[inline]
    pub fn retain_user_definable(&mut self) {
        self.entries.retain(|e, _| e.is_user_defineable())
    }
}

impl<E, T> Default for Tags<E, T> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Tags<<T as Tag>::Entry, T>
where
    <T as Tag>::Entry: Hash + Eq,
    T: Hash + Eq + Tag,
{
    /// Whether this tags contains the given tag.
    #[inline]
    pub fn contains(&self, tag: &T) -> bool {
        self.entries
            .get(&tag.as_entry())
            .map_or(false, |set| set.contains(tag))
    }

    /// Removes a tag from its entry, and returns whether it was
    /// there before.
    #[inline]
    pub fn remove(&mut self, tag: &T) -> bool {
        self.entries
            .get_mut(&tag.as_entry())
            .map_or(false, |tags| tags.remove(tag))
    }

    /// Gets tag set from given entry.
    #[inline]
    pub fn from_entry(&self, entry: &<T as Tag>::Entry) -> Option<&HashSet<T>> {
        self.entries.get(entry)
    }

    /// Gets mutable tag set from given entry.
    #[inline]
    pub fn from_entry_mut(&mut self, entry: &<T as Tag>::Entry) -> Option<&mut HashSet<T>> {
        self.entries.get_mut(entry)
    }
}

impl<T> Tags<<T as Tag>::Entry, T>
where
    <T as Tag>::Entry: Hash + Eq + ToOwned<Owned = <T as Tag>::Entry>,
    T: Hash + Eq + Tag,
{
    /// Inserts a tag into its entry, and returns whether the tag
    /// was there before.
    #[inline]
    pub fn insert(&mut self, tag: T) -> bool {
        self.from_entry_mut_or_init(&tag.as_entry()).insert(tag)
    }

    /// Gets tags set of given entry, or create one if absent.
    fn from_entry_mut_or_init(&mut self, entry: &<T as Tag>::Entry) -> &mut HashSet<T> {
        if !self.entries.contains_key(entry) {
            self.entries.insert(entry.to_owned(), HashSet::new());
        }
        self.entries.get_mut(entry).unwrap()
    }
}

impl<T> Tags<<T as Tag>::Entry, T>
where
    <T as Tag>::Entry: Hash + Eq + PermissionEntry,
    T: Hash + Eq + Tag + AsPermission,
{
    /// Whether this tags contains the given permission group,
    /// or contains a permission group that contains the permission
    /// of given permission group.
    pub fn contains_permission(&self, permission: &T) -> bool {
        let Some(perm) = permission.as_permission() else {
            return false;
        };
        if permission.as_entry() != <<T as Tag>::Entry as PermissionEntry>::VALUE {
            return false;
        }
        self.entries
            .get(&permission.as_entry())
            .map_or(false, |set| {
                set.contains(permission)
                    || set.iter().any(|p| {
                        p.as_permission()
                            .expect("permission tags should be permission groups")
                            .contains(perm)
                    })
            })
    }
}

impl<T> Tags<<T as Tag>::Entry, T>
where
    <T as Tag>::Entry: Hash + Eq + PermissionEntry,
    T: Hash + Eq + Tag + AsPermission + From<<T as AsPermission>::Permission>,
{
    /// Initializes permissions of this tags.
    ///
    /// See [`Permission::default_set`].
    pub fn initialize_permissions(&mut self) {
        self.entries.insert(
            <<T as Tag>::Entry as PermissionEntry>::VALUE,
            <T as AsPermission>::Permission::default_set()
                .into_iter()
                .map(T::from)
                .collect(),
        );
    }
}

impl<E, T: Serialize> Serialize for Tags<E, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq =
            serializer.serialize_seq(Some(self.entries.values().map(|tags| tags.len()).sum()))?;
        for tags in self.entries.values() {
            for tag in tags {
                seq.serialize_element(tag)?;
            }
        }
        seq.end()
    }
}

impl<'de, T> Deserialize<'de> for Tags<<T as Tag>::Entry, T>
where
    T: Deserialize<'de> + Tag + Hash + Eq,
    <T as Tag>::Entry: Hash + Eq,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        pub struct TVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T> serde::de::Visitor<'de> for TVisitor<T>
        where
            T: Deserialize<'de> + Tag + Hash + Eq,
            <T as Tag>::Entry: Hash + Eq,
        {
            type Value = Tags<<T as Tag>::Entry, T>;

            #[inline]
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a flat sequence of tags")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut this = Tags::new();
                while let Some(tag) = seq.next_element::<T>()? {
                    let entry = tag.as_entry();
                    if !this.entries.contains_key(&entry) {
                        this.entries.insert(tag.as_entry(), [tag].into());
                    } else {
                        this.entries.get_mut(&entry).unwrap().insert(tag);
                    }
                }
                Ok(this)
            }
        }

        deserializer.deserialize_seq(TVisitor(std::marker::PhantomData))
    }
}

/// Entry contains a `Permission` variant.
pub trait PermissionEntry: Sized {
    /// The `Permission` variant.
    const VALUE: Self;
}

/// Entry which values are able to initialized by
/// users.
pub trait UserDefinableEntry {
    /// Whether this entry is user definable.
    fn is_user_defineable(&self) -> bool;
}

/// Tag types that can obtain their entries.
pub trait Tag {
    /// The type of entry.
    type Entry;

    /// Entry of this tag.
    fn as_entry(&self) -> Self::Entry;
}

/// Tag types that presents permissions, optionally.
pub trait AsPermission {
    /// Permission type of this tag.
    type Permission: Permission;

    /// Represents this tag as a permission.
    fn as_permission(&self) -> Option<&Self::Permission>;
}
