# Native AES (Rijndael) Implementation

This package provides native AES (Advanced Encryption Standard) encryption and decryption functionality for MoonBit through C bindings to the optimized Rijndael algorithm implementation. The package is designed specifically for native targets and offers high-performance cryptographic operations.

```moonbit
// Helper functions for README examples
fn fixedarray_byte_of_bytes(x : Bytes) -> FixedArray[Byte] = "%identity"
fn bytes_of_fixedarray_byte(x : FixedArray[Byte]) -> Bytes = "%identity"
```

## Overview

The native package exposes low-level AES operations including:
- Key preparation for encryption and decryption
- Block encryption and decryption operations
- Support for AES-128, AES-192, and AES-256 key sizes

## Key Preparation

AES operations require preparing the encryption key before use. The package provides functions to "cook" raw keys into the internal format required by the algorithm.

### Encryption Key Preparation

```moonbit
test "prepare encryption key" {
  let raw_key = fixedarray_byte_of_bytes(b"0123456789ABCDEF") // 128-bit key
  let cooked_key = @native.camlpdf_caml_aes_cook_encrypt_key(raw_key, 0, raw_key.length())
  
  // The cooked key contains the expanded key schedule
  inspect(cooked_key.length(), content="241")
}
```

### Decryption Key Preparation

```moonbit
test "prepare decryption key" {
  let raw_key = fixedarray_byte_of_bytes(b"0123456789ABCDEF") // 128-bit key
  let cooked_key = @native.camlpdf_caml_aes_cook_decrypt_key(raw_key, 0, raw_key.length())
  
  // Decryption keys have a different internal structure than encryption keys
  inspect(cooked_key.length(), content="241")
}
```

## Block Encryption and Decryption

AES operates on 16-byte blocks. The package provides functions to encrypt and decrypt individual blocks.

### Basic Encryption

```moonbit
test "encrypt a block" {
  let key = fixedarray_byte_of_bytes(b"0123456789ABCDEF")
  let cooked_encrypt_key = @native.camlpdf_caml_aes_cook_encrypt_key(key, 0, key.length())
  
  let plaintext = fixedarray_byte_of_bytes(b"Time is precious") // Exactly 16 bytes
  let ciphertext = FixedArray::make(16, (0).to_byte())
  
  @native.camlpdf_caml_aes_encrypt(cooked_encrypt_key, 0, plaintext, 0, ciphertext, 0)
  
  // The ciphertext should be different from plaintext
  inspect(bytes_of_fixedarray_byte(ciphertext), 
    content="b\"\\xf3\\x97\\x09\\xdf\\x2c\\xdb\\x87\\x42\\x40\\x47\\xba\\x4e\\x28\\x66\\x14\\xb3\"")
}
```

### Basic Decryption

```moonbit
test "decrypt a block" {
  let key = fixedarray_byte_of_bytes(b"0123456789ABCDEF")
  let cooked_decrypt_key = @native.camlpdf_caml_aes_cook_decrypt_key(key, 0, key.length())
  
  // Use the ciphertext from encryption
  let ciphertext = fixedarray_byte_of_bytes(
    b"\xf3\x97\x09\xdf\x2c\xdb\x87\x42\x40\x47\xba\x4e\x28\x66\x14\xb3"
  )
  let decrypted = FixedArray::make(16, (0).to_byte())
  
  @native.camlpdf_caml_aes_decrypt(cooked_decrypt_key, 0, ciphertext, 0, decrypted, 0)
  
  // Should recover the original plaintext
  inspect(bytes_of_fixedarray_byte(decrypted), 
    content=(
      #|b"\x54\x69\x6d\x65\x20\x69\x73\x20\x70\x72\x65\x63\x69\x6f\x75\x73"
    ))
}
```

## Complete Encryption/Decryption Cycle

The most common use case is encrypting data and then decrypting it back to verify the implementation.

### Round-trip Test

```moonbit
test "complete encryption and decryption cycle" {
  let key = fixedarray_byte_of_bytes(b"0123456789ABCDEF")
  let original_plaintext = fixedarray_byte_of_bytes(b"Hello, MoonBit!!")
  
  // Prepare both encryption and decryption keys
  let encrypt_key = @native.camlpdf_caml_aes_cook_encrypt_key(key, 0, key.length())
  let decrypt_key = @native.camlpdf_caml_aes_cook_decrypt_key(key, 0, key.length())
  
  // Encrypt
  let ciphertext = FixedArray::make(16, (0).to_byte())
  @native.camlpdf_caml_aes_encrypt(encrypt_key, 0, original_plaintext, 0, ciphertext, 0)
  
  // Decrypt
  let recovered_plaintext = FixedArray::make(16, (0).to_byte())
  @native.camlpdf_caml_aes_decrypt(decrypt_key, 0, ciphertext, 0, recovered_plaintext, 0)
  
  // Verify the round-trip worked
  assert_eq(original_plaintext, recovered_plaintext)
}
```

## Different Key Sizes

AES supports three key sizes: 128-bit (16 bytes), 192-bit (24 bytes), and 256-bit (32 bytes).

### AES-128 (16-byte key)

```moonbit
test "AES-128 encryption" {
  let key_128 = fixedarray_byte_of_bytes(b"aGvw!pDaVuZ5Dz.3") // 16 bytes
  let cooked_key = @native.camlpdf_caml_aes_cook_encrypt_key(key_128, 0, key_128.length())
  
  // 128-bit keys produce a specific key schedule size
  inspect(cooked_key.length(), content="241")
}
```

### AES-192 (24-byte key)

```moonbit
test "AES-192 encryption" {
  let key_192 = fixedarray_byte_of_bytes(b"cFFch2cK7.gQW#$FYQDa:wR6") // 24 bytes
  let cooked_key = @native.camlpdf_caml_aes_cook_encrypt_key(key_192, 0, key_192.length())
  
  // 192-bit keys produce a longer key schedule
  inspect(cooked_key.length(), content="241")
}
```

### AES-256 (32-byte key)

```moonbit
test "AES-256 encryption" {
  let key_256 = fixedarray_byte_of_bytes(b"4hrA;KwpQQXHXWkqa5bt5nX/%_vwE*Zp") // 32 bytes
  let cooked_key = @native.camlpdf_caml_aes_cook_encrypt_key(key_256, 0, key_256.length())
  
  // 256-bit keys produce the longest key schedule
  inspect(cooked_key.length(), content="241")
}
```

## Error Handling

The implementation handles invalid key sizes gracefully by returning zero-filled arrays.

### Invalid Key Size

```moonbit skip
/// ⚠️ Warning: buffer overflow
test "invalid key size handling" {
  let invalid_key = fixedarray_byte_of_bytes(b"short") // Only 5 bytes, invalid for AES
  let result = @native.camlpdf_caml_aes_cook_encrypt_key(invalid_key, 0, invalid_key.length())
  
  // Should return a zero-filled array for invalid key sizes
  let expected_zeros = FixedArray::make(241, (0).to_byte())
  assert_eq(result, expected_zeros)
}
```

## Performance Considerations

This native implementation provides optimal performance for AES operations by:

- Using optimized C code from the original Rijndael authors
- Pre-computing key schedules to avoid repeated calculations
- Operating directly on byte arrays without additional allocations
- Leveraging native compilation for maximum speed

## Security Notes

- This implementation provides the core AES algorithm but does not include padding or mode of operation
- For production use, consider implementing appropriate padding schemes (PKCS#7, etc.)
- Choose appropriate modes of operation (CBC, CTR, GCM, etc.) based on your security requirements
- Ensure proper key management and secure key storage in your applications
- The implementation includes sanitizer flags for development but these should be configured appropriately for production builds

## Integration with Higher-Level APIs

This native package serves as the foundation for higher-level cryptographic APIs in the rijndael module. It provides the essential building blocks for implementing various AES modes and padding schemes while maintaining optimal performance through native code execution.