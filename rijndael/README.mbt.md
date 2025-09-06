# Rijndael (AES) Encryption Implementation

A pure MoonBit implementation of the Rijndael (AES) encryption algorithm. This package provides the core AES encryption and decryption functionality with support for 128-bit, 192-bit, and 256-bit keys.

```moonbit
// Helper functions and constants for README examples
fn fixedarray_byte_of_bytes(x : Bytes) -> FixedArray[Byte] = "%identity"
fn bytes_of_fixedarray_byte(x : FixedArray[Byte]) -> Bytes = "%identity"
const Cooked_key_NR_offset : Int = 240
const Cooked_key_size : Int = 241
```

## Key Features

- **Standard AES Support**: Implements the Rijndael algorithm as standardized in AES
- **Multiple Key Sizes**: Supports 128-bit, 192-bit, and 256-bit keys
- **Efficient Implementation**: Optimized with lookup tables for fast encryption/decryption
- **Memory Safe**: Written in MoonBit with proper bounds checking
- **Block Processing**: Operates on 16-byte blocks as per AES specification

## Key Management

The package provides functions to prepare encryption and decryption keys from raw byte arrays. Keys must be properly "cooked" before use in encryption operations.

### Preparing Encryption Keys

```moonbit
test "prepare encryption key" {
  let key_bytes = b"0123456789ABCDEF"  // 128-bit key
  let key_array = fixedarray_byte_of_bytes(key_bytes)
  
  let encrypt_key = @rijndael.camlpdf_caml_aes_cook_encrypt_key(
    key_array, 0, key_array.length()
  )
  
  // The cooked key contains the expanded round keys
  inspect(encrypt_key.length(), content="241")
}
```

### Preparing Decryption Keys

```moonbit
test "prepare decryption key" {
  let key_bytes = b"0123456789ABCDEF"  // 128-bit key
  let key_array = fixedarray_byte_of_bytes(key_bytes)
  
  let decrypt_key = @rijndael.camlpdf_caml_aes_cook_decrypt_key(
    key_array, 0, key_array.length()
  )
  
  // Decryption key is also 241 bytes for expanded round keys
  inspect(decrypt_key.length(), content="241")
}
```

## Key Size Support

The algorithm automatically detects key sizes and sets up the appropriate number of rounds:

```moonbit
test "different key sizes" {
  // 128-bit key (10 rounds)
  let key_128 = fixedarray_byte_of_bytes(b"0123456789ABCDEF")
  let enc_128 = @rijndael.camlpdf_caml_aes_cook_encrypt_key(
    key_128, 0, key_128.length()
  )
  inspect(enc_128[Cooked_key_NR_offset].to_int(), content="10")
  
  // 192-bit key (12 rounds)  
  let key_192 = fixedarray_byte_of_bytes(b"0123456789ABCDEF01234567")
  let enc_192 = @rijndael.camlpdf_caml_aes_cook_encrypt_key(
    key_192, 0, key_192.length()
  )
  inspect(enc_192[Cooked_key_NR_offset].to_int(), content="12")
  
  // 256-bit key (14 rounds)
  let key_256 = fixedarray_byte_of_bytes(b"0123456789ABCDEF0123456789ABCDEF")
  let enc_256 = @rijndael.camlpdf_caml_aes_cook_encrypt_key(
    key_256, 0, key_256.length()
  )
  inspect(enc_256[Cooked_key_NR_offset].to_int(), content="14")
}
```

## Block Encryption

AES operates on 16-byte blocks. The package provides functions to encrypt single blocks:

```moonbit
test "block encryption" {
  let key = fixedarray_byte_of_bytes(b"0123456789ABCDEF")
  let plaintext = fixedarray_byte_of_bytes(b"Time is precious")
  
  // Prepare encryption key
  let encrypt_key = @rijndael.camlpdf_caml_aes_cook_encrypt_key(
    key, 0, key.length()
  )
  
  // Encrypt the block
  let ciphertext = FixedArray::make(16, b'\x00')
  @rijndael.camlpdf_caml_aes_encrypt(
    encrypt_key, 0,           // cooked key and offset
    plaintext, 0,             // source data and offset  
    ciphertext, 0             // destination and offset
  )
  
  // Verify encryption occurred
  if plaintext == ciphertext {
    abort("Encryption did not occur")
  }
  inspect(ciphertext.length(), content="16")
}
```

## Block Decryption

Decryption reverses the encryption process to recover the original plaintext:

```moonbit
test "block decryption" {
  let key = fixedarray_byte_of_bytes(b"0123456789ABCDEF")
  let plaintext = fixedarray_byte_of_bytes(b"Time is precious")
  
  // Prepare both keys
  let encrypt_key = @rijndael.camlpdf_caml_aes_cook_encrypt_key(
    key, 0, key.length()
  )
  let decrypt_key = @rijndael.camlpdf_caml_aes_cook_decrypt_key(
    key, 0, key.length()
  )
  
  // Encrypt then decrypt
  let ciphertext = FixedArray::make(16, b'\x00')
  let recovered = FixedArray::make(16, b'\x00')
  
  @rijndael.camlpdf_caml_aes_encrypt(
    encrypt_key, 0, plaintext, 0, ciphertext, 0
  )
  @rijndael.camlpdf_caml_aes_decrypt(
    decrypt_key, 0, ciphertext, 0, recovered, 0
  )
  
  // Verify round-trip success
  assert_eq(plaintext, recovered)
}
```

## Multiple Block Processing

For encrypting larger amounts of data, you can process multiple 16-byte blocks:

```moonbit
test "multiple blocks" {
  let key = fixedarray_byte_of_bytes(b"0123456789ABCDEF")
  let encrypt_key = @rijndael.camlpdf_caml_aes_cook_encrypt_key(
    key, 0, key.length()
  )
  let decrypt_key = @rijndael.camlpdf_caml_aes_cook_decrypt_key(
    key, 0, key.length()
  )
  
  // Three 16-byte blocks
  let block1 = fixedarray_byte_of_bytes(b"Time is precious")
  let block2 = fixedarray_byte_of_bytes(b"MoonBit is great")
  let block3 = fixedarray_byte_of_bytes(b"Rijndael AES enc")
  
  let ciphertext = FixedArray::make(48, b'\x00')  // 3 blocks
  let decrypted = FixedArray::make(48, b'\x00')
  
  // Encrypt each block at different offsets
  @rijndael.camlpdf_caml_aes_encrypt(encrypt_key, 0, block1, 0, ciphertext, 0)
  @rijndael.camlpdf_caml_aes_encrypt(encrypt_key, 0, block2, 0, ciphertext, 16)
  @rijndael.camlpdf_caml_aes_encrypt(encrypt_key, 0, block3, 0, ciphertext, 32)
  
  // Decrypt each block
  @rijndael.camlpdf_caml_aes_decrypt(decrypt_key, 0, ciphertext, 0, decrypted, 0)
  @rijndael.camlpdf_caml_aes_decrypt(decrypt_key, 0, ciphertext, 16, decrypted, 16)
  @rijndael.camlpdf_caml_aes_decrypt(decrypt_key, 0, ciphertext, 32, decrypted, 32)
  
  // Verify each block was recovered correctly
  let recovered_bytes = bytes_of_fixedarray_byte(decrypted)
  assert_eq(b"Time is precious", recovered_bytes[0:16].to_bytes())
  assert_eq(b"MoonBit is great", recovered_bytes[16:32].to_bytes()) 
  assert_eq(b"Rijndael AES enc", recovered_bytes[32:48].to_bytes())
}
```

## Error Handling and Validation

The implementation includes proper bounds checking and validation:

```moonbit
test "key validation" {
  // Valid key sizes: 16, 24, 32 bytes (128, 192, 256 bits)
  let valid_keys = [
    b"0123456789ABCDEF",                    // 16 bytes = 128 bits
    b"0123456789ABCDEF01234567",            // 24 bytes = 192 bits  
    b"0123456789ABCDEF0123456789ABCDEF"     // 32 bytes = 256 bits
  ]
  
  for key_bytes in valid_keys {
    let key_array = fixedarray_byte_of_bytes(key_bytes)
    let encrypt_key = @rijndael.camlpdf_caml_aes_cook_encrypt_key(
      key_array, 0, key_array.length()
    )
    // Should complete without error
    assert_eq(encrypt_key.length(), 241)
  }
}
```

## Advanced Usage with Offsets

The package supports offset-based operations for working with larger buffers:

```moonbit
test "offset operations" {
  let key = fixedarray_byte_of_bytes(b"0123456789ABCDEF")
  let encrypt_key = @rijndael.camlpdf_caml_aes_cook_encrypt_key(
    key, 0, key.length()
  )
  let decrypt_key = @rijndael.camlpdf_caml_aes_cook_decrypt_key(
    key, 0, key.length()
  )
  
  // Create a larger buffer with data at specific offset
  let large_buffer = FixedArray::make(64, b'\x00')
  let plaintext_data = b"Time is precious"
  
  // Copy plaintext to offset 16 in the buffer
  for i in 0..<16 {
    large_buffer[16 + i] = plaintext_data[i]
  }
  
  let ciphertext_buffer = FixedArray::make(64, b'\x00')
  let recovered_buffer = FixedArray::make(64, b'\x00')
  
  // Encrypt from offset 16 to offset 32
  @rijndael.camlpdf_caml_aes_encrypt(
    encrypt_key, 0, large_buffer, 16, ciphertext_buffer, 32
  )
  
  // Decrypt from offset 32 to offset 48  
  @rijndael.camlpdf_caml_aes_decrypt(
    decrypt_key, 0, ciphertext_buffer, 32, recovered_buffer, 48
  )
  
  // Verify the data was correctly processed with offsets
  for i in 0..<16 {
    assert_eq(large_buffer[16 + i], recovered_buffer[48 + i])
  }
}
```

## API Reference

### Key Functions

- `camlpdf_caml_aes_cook_encrypt_key(key, start, end)` - Prepare encryption key from raw bytes
- `camlpdf_caml_aes_cook_decrypt_key(key, start, end)` - Prepare decryption key from raw bytes  
- `camlpdf_caml_aes_encrypt(cooked_key, key_offset, src, src_offset, dst, dst_offset)` - Encrypt one block
- `camlpdf_caml_aes_decrypt(cooked_key, key_offset, src, src_offset, dst, dst_offset)` - Decrypt one block

### Constants

- `Cooked_key_size` - Size of a cooked key buffer (241 bytes)
- `Cooked_key_NR_offset` - Offset where round count is stored in cooked key (240)

### Notes

- All operations work on 16-byte blocks
- Keys can be 128, 192, or 256 bits (16, 24, or 32 bytes)
- Cooked keys contain expanded round keys plus metadata
- The implementation uses big-endian byte ordering internally
- Offset parameters allow efficient processing of larger buffers