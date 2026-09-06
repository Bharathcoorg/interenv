/// Safe atomic canonicalization routines avoiding symlink race conditions.
pub mod safe_canonicalize;

pub use safe_canonicalize::safe_canonicalize;
