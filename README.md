# Rijndael (AES) Encryption for MoonBit

A comprehensive MoonBit implementation of the Rijndael (AES) encryption algorithm, providing both pure MoonBit and native C-based implementations for optimal performance and compatibility.

## Overview

This project implements the Advanced Encryption Standard (AES), also known as the Rijndael cipher, for the MoonBit programming language. AES is a symmetric encryption algorithm widely used for securing sensitive data. This implementation supports all standard key sizes (128-bit, 192-bit, and 256-bit) and provides two complementary approaches:

- **Pure MoonBit Implementation**: A complete implementation written entirely in MoonBit for maximum portability and safety
- **Native C Implementation**: High-performance implementation using optimized C code with MoonBit bindings for maximum speed

## Key Features

- **Multiple Key Sizes**: Full support for AES-128, AES-192, and AES-256
- **Block Cipher Operations**: Standard 16-byte block encryption and decryption
- **Dual Implementations**: Choose between pure MoonBit or native C performance
- **Memory Safe**: Proper bounds checking and safe memory operations
- **Standard Compliant**: Implements the official AES specification
- **Optimized Performance**: Lookup table optimizations and native code for speed
- **Cross-Platform**: Works across all MoonBit supported targets

## Project Structure

This project consists of two main packages:

### 📦 [Rijndael Package](./rijndael/README.mbt.md)
Pure MoonBit implementation of the AES algorithm. This package provides:
- Complete AES encryption/decryption in safe MoonBit code
- Support for all standard key sizes (128/192/256-bit)
- Efficient lookup table implementation
- Cross-platform compatibility
- Memory-safe operations with bounds checking

### 🚀 [Native Package](./native/README.mbt.md)
High-performance native implementation using C bindings. This package offers:
- Optimized C implementation from the original Rijndael authors
- Maximum performance through native compilation
- Direct byte array operations
- Minimal overhead for high-throughput applications
- Secure memory handling

## Use Cases

- **Secure Data Storage**: Encrypt sensitive data before storing to disk or database
- **Network Communication**: Secure data transmission over networks
- **File Encryption**: Protect files and documents with strong encryption
- **Cryptographic Protocols**: Building block for more complex security protocols
- **Educational**: Learn about symmetric encryption and the AES algorithm

## Performance Considerations

- **Native Package**: Choose for maximum performance in computational-intensive applications
- **Rijndael Package**: Choose for maximum portability and when native compilation isn't available
- **Memory Usage**: Both implementations use minimal memory with efficient key scheduling
- **Block Processing**: Designed for efficient processing of multiple blocks

## Security Notes

- This implementation provides the core AES algorithm
- For production use, implement appropriate:
  - Padding schemes (PKCS#7, etc.)
  - Modes of operation (CBC, CTR, GCM, etc.)
  - Proper key management and secure storage
  - Initialization vectors (IVs) for non-ECB modes

## Development and Testing

The project includes comprehensive test suites for both implementations:

```bash
# Run all tests
moon test

# Test specific package
moon test --package rijndael
moon test --package native

# Build for different targets
moon build --target native    # For native performance
moon build --target wasm     # For WebAssembly targets
```

## Documentation

- [📖 Rijndael Package Documentation](./rijndael/README.mbt.md) - Pure MoonBit implementation
- [📖 Native Package Documentation](./native/README.mbt.md) - High-performance C implementation

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests to help improve this AES implementation for the MoonBit community.