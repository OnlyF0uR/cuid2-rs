# cuid2-rs

[![Crates.io](https://img.shields.io/crates/v/cuid2-rs.svg)](https://crates.io/crates/cuid2-rs)
[![Documentation](https://docs.rs/cuid2-rs/badge.svg)](https://docs.rs/cuid2-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust implementation of CUID2 (Collision-resistant Unique IDentifiers) - secure, short, URL-friendly unique string IDs.

## Features

- **Secure**: Cryptographically strong random generation using ChaCha20 and SHA3-512
- **Collision-resistant**: Designed to minimize the risk of ID collisions
- **URL-friendly**: Contains only lowercase letters and numbers
- **Configurable**: Customize ID length based on your requirements
- **Thread-safe**: Safe for concurrent use in multi-threaded applications

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
cuid2-rs = "0.1.0"
```

## Usage

### Basic Usage

```rust
use cuid2_rs::generate;

fn main() {
    // Generate a CUID with default length (24 characters)
    let id = generate().unwrap();
    println!("Generated CUID: {}", id);
    // Example output: "a1b2c3d4e5f6g7h8i9j0k1l2m3"
}
```

### Custom Length

```rust
use cuid2_rs::generate_cuid;

fn main() {
    // Generate a shorter CUID (10 characters)
    let short_id = generate_cuid(10).unwrap();
    println!("Short CUID: {}", short_id);
    // Example output: "a1b2c3d4e5"

    // Generate a longer CUID (32 characters)
    let long_id = generate_cuid(32).unwrap();
    println!("Long CUID: {}", long_id);
    // Example output: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
}
```

### Validation

```rust
use cuid2_rs::{is_valid_cuid, MIN_LENGTH, MAX_LENGTH};

fn main() {
    let id = "a1b2c3d4e5";
    let is_valid = is_valid_cuid(id, MIN_LENGTH, MAX_LENGTH);
    println!("Is valid CUID: {}", is_valid);

    // Invalid CUID (starts with a number)
    let invalid_id = "1abc123";
    let is_valid = is_valid_cuid(invalid_id, MIN_LENGTH, MAX_LENGTH);
    assert!(!is_valid);
}
```

## How It Works

CUID2 generates secure, collision-resistant IDs by combining several sources of entropy:

1. A random lowercase letter at the beginning (for database indexing benefits)
2. Current timestamp in milliseconds
3. A counter to prevent collisions in rapid generation
4. Cryptographically secure random values
5. A system fingerprint hash to prevent collisions in distributed systems

The result is securely hashed with SHA3-512 and formatted to the desired length.

## Configuration

The library provides several constants that you can use:

```rust
pub const DEFAULT_LENGTH: usize = 24;  // Default CUID length
pub const MAX_LENGTH: usize = 32;      // Maximum allowed length
pub const MIN_LENGTH: usize = 2;       // Minimum allowed length
```

## Error Handling

The `generate()` and `generate_cuid()` functions return a `Result` that can contain errors:

```rust
use cuid2_rs::{generate_cuid, CuidError};

fn main() {
    // Length is too large (over MAX_LENGTH)
    let result = generate_cuid(100);
    match result {
        Err(CuidError::InvalidLength(len, min, max)) => {
            println!("Error: Invalid length {} (must be between {} and {})",
                     len, min, max);
        },
        _ => panic!("Unexpected result"),
    }
}
```

## Performance

CUID2 is designed to be efficient while maintaining security. The implementation uses:

- ChaCha20 for secure random number generation
- SHA3-512 for cryptographic hashing
- Atomic operations for thread safety

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgements

This is a Rust implementation of the CUID2 algorithm, originally developed by Eric Elliott.
