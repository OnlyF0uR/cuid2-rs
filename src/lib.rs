use rand::rngs::OsRng;
use rand::{Rng, SeedableRng, TryRngCore};
use rand_chacha::ChaCha20Rng;
use sha3::{Digest, Sha3_512};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Default length for generated CUIDs
pub const DEFAULT_LENGTH: usize = 24;
/// Maximum length for generated CUIDs
pub const MAX_LENGTH: usize = 32;
/// Minimum length for valid CUIDs
pub const MIN_LENGTH: usize = 2;
/// Alphabet for generating random letters
const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
/// Counter for ensuring uniqueness
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Error type for CUID generation and validation
#[derive(Debug)]
pub enum CuidError {
    InvalidLength(usize, usize, usize),
    SystemTimeError(std::time::SystemTimeError),
    RandChaChaError(rand_chacha::rand_core::OsError),
}

impl std::fmt::Display for CuidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CuidError::InvalidLength(len, min, max) => {
                write!(
                    f,
                    "Invalid CUID length: {}, expected between {} and {}",
                    len, min, max
                )
            }
            CuidError::SystemTimeError(err) => {
                write!(f, "System time error: {}", err)
            }
            CuidError::RandChaChaError(err) => {
                write!(f, "ChaCha RNG error: {}", err)
            }
        }
    }
}

impl std::error::Error for CuidError {}

impl From<std::time::SystemTimeError> for CuidError {
    fn from(err: std::time::SystemTimeError) -> Self {
        CuidError::SystemTimeError(err)
    }
}

impl From<rand_chacha::rand_core::OsError> for CuidError {
    fn from(err: rand_chacha::rand_core::OsError) -> Self {
        CuidError::RandChaChaError(err)
    }
}

/// Result type for CUID operations
pub type Result<T> = std::result::Result<T, CuidError>;

/// Generates random alphanumeric entropy of a given length.
fn generate_entropy(length: usize) -> Result<String> {
    // Use OsRng to generate a random seed
    let seed = OsRng.try_next_u64()?;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    Ok((0..length)
        .map(|_| char::from_digit(rng.random_range(0..36) as u32, 36).unwrap())
        .collect())
}

/// Computes a SHA3-512 hash and returns a truncated hexadecimal string.
fn compute_hash(input: &str, length: usize) -> String {
    let mut hasher = Sha3_512::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    let hash_str = hex::encode(result);
    hash_str[..length].to_string()
}

/// Generates a random lowercase letter.
fn generate_random_letter() -> Result<char> {
    // Use OsRng to generate a random seed
    let seed = OsRng.try_next_u64()?;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    Ok(ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
}

/// Creates a fingerprint to help prevent collisions in distributed systems.
fn generate_fingerprint() -> Result<String> {
    let entropy = generate_entropy(MAX_LENGTH)?;
    Ok(compute_hash(&entropy, MAX_LENGTH))
}

/// Generates a unique identifier similar to CUID2.
///
/// # Arguments
/// * `length` - The desired length of the CUID
///
/// # Returns
/// * `Result<String>` - The generated CUID or an error
///
/// # Examples
/// ```
/// use cuid2_rs::generate_cuid;
///
/// let id = generate_cuid(24).unwrap();
/// assert_eq!(id.len(), 24);
/// ```
pub fn generate_cuid(length: usize) -> Result<String> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(CuidError::InvalidLength(length, MIN_LENGTH, MAX_LENGTH));
    }

    let first_letter = generate_random_letter()?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .to_string();
    let counter_value = COUNTER.fetch_add(1, Ordering::SeqCst).to_string();
    let salt = generate_entropy(length)?;
    let fingerprint = generate_fingerprint()?;

    let hash_input = format!("{}{}{}{}", timestamp, salt, counter_value, fingerprint);
    let hashed = compute_hash(&hash_input, length);

    Ok(format!("{}{}", first_letter, &hashed[1..length]))
}

/// Generate a CUID with the default length
///
/// # Returns
/// * `Result<String>` - The generated CUID or an error
///
/// # Examples
/// ```
/// use cuid2_rs::generate;
///
/// let id = generate().unwrap();
/// assert_eq!(id.len(), cuid2_rs::DEFAULT_LENGTH);
/// ```
pub fn generate() -> Result<String> {
    generate_cuid(DEFAULT_LENGTH)
}

/// Validates whether a given ID conforms to CUID2 format.
///
/// # Arguments
/// * `id` - The ID to validate
/// * `min_length` - Minimum acceptable length
/// * * `max_length` - Maximum acceptable length
///
/// # Returns
/// * `bool` - Whether the ID is valid
///
/// # Examples
/// ```
/// use cuid2_rs::{generate, is_valid_cuid, MIN_LENGTH, MAX_LENGTH};
///
/// let id = generate().unwrap();
/// assert!(is_valid_cuid(&id, MIN_LENGTH, MAX_LENGTH));
/// ```
pub fn is_valid_cuid(id: &str, min_length: usize, max_length: usize) -> bool {
    if id.is_empty() {
        return false;
    }

    let first_char = id.chars().next().unwrap();
    let starts_with_letter = first_char.is_ascii_lowercase();
    let valid_format = id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let valid_length = id.len() >= min_length && id.len() <= max_length;

    starts_with_letter && valid_format && valid_length
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_cuid() {
        let id = generate_cuid(DEFAULT_LENGTH).unwrap();
        assert!(is_valid_cuid(&id, MIN_LENGTH, MAX_LENGTH));
        assert_eq!(id.len(), DEFAULT_LENGTH);
    }

    #[test]
    fn test_generate_default() {
        let id = generate().unwrap();
        assert!(is_valid_cuid(&id, MIN_LENGTH, MAX_LENGTH));
        assert_eq!(id.len(), DEFAULT_LENGTH);
    }

    #[test]
    fn test_is_valid_cuid() {
        let id = generate_cuid(DEFAULT_LENGTH).unwrap();
        assert!(is_valid_cuid(&id, MIN_LENGTH, MAX_LENGTH));
    }

    #[test]
    fn test_invalid_cuid_length() {
        assert!(!is_valid_cuid("a", MIN_LENGTH, MAX_LENGTH));
        assert!(!is_valid_cuid(
            "a123456789012345678901234567890123",
            MIN_LENGTH,
            MAX_LENGTH
        ));
    }

    #[test]
    fn test_invalid_cuid_format() {
        assert!(!is_valid_cuid("1abc123", MIN_LENGTH, MAX_LENGTH)); // Must start with a letter
        assert!(!is_valid_cuid("abc-123", MIN_LENGTH, MAX_LENGTH)); // No special characters allowed
    }

    #[test]
    fn test_generate_entropy() {
        let entropy = generate_entropy(10).unwrap();
        assert_eq!(entropy.len(), 10);
        assert!(entropy.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_random_letter() {
        let letter = generate_random_letter().unwrap();
        assert!(ALPHABET.contains(&(letter as u8)));
    }

    #[test]
    fn test_compute_hash() {
        let input = "test_string";
        let hashed = compute_hash(input, 16);
        assert_eq!(hashed.len(), 16);
    }

    #[test]
    fn test_invalid_length_error() {
        let result = generate_cuid(MAX_LENGTH + 1);
        assert!(result.is_err());
        match result {
            Err(CuidError::InvalidLength(len, min, max)) => {
                assert_eq!(len, MAX_LENGTH + 1);
                assert_eq!(min, MIN_LENGTH);
                assert_eq!(max, MAX_LENGTH);
            }
            _ => panic!("Expected InvalidLength error"),
        }
    }

    #[test]
    fn test_first_char_is_letter() {
        for _ in 0..100 {
            let id = generate().unwrap();
            assert!(id.chars().next().unwrap().is_ascii_lowercase());
        }
    }
}
