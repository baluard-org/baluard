//! Cryptographic utility helpers for the daemon.
//!
//! R7-2: Constant-time comparison for session token verification.

/// Constant-time byte comparison using the `subtle` crate.
/// Prevents timing side channels when comparing session tokens or other secrets.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_slices() {
        assert!(constant_time_eq(b"abc123", b"abc123"));
    }

    #[test]
    fn unequal_slices() {
        assert!(!constant_time_eq(b"abc123", b"abc124"));
    }

    #[test]
    fn different_lengths() {
        assert!(!constant_time_eq(b"short", b"muchlonger"));
    }

    #[test]
    fn empty_slices() {
        assert!(constant_time_eq(b"", b""));
    }
}
