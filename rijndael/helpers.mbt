///|
/// Helper function to convert bytes to FixedArray[Byte]
fn fixedarray_byte_of_bytes(x : Bytes) -> FixedArray[Byte] = "%identity"

///|
/// Helper function to convert FixedArray[Byte] to bytes
fn bytes_of_fixedarray_byte(x : FixedArray[Byte]) -> Bytes = "%identity"

///|
/// Helper function to convert ArrayView[Byte] to FixedArray[Byte]
fn fixedarray_of_arrayview_byte(x : ArrayView[Byte]) -> FixedArray[Byte] = "%identity"

///|
/// Cook an AES encryption key from bytes
pub fn camlpdf_caml_aes_cook_encrypt_key(
  key : FixedArray[Byte],
  start : Int,
  end : Int,
) -> FixedArray[Byte] {
  let key_bits = (end - start) * 8
  let cooked_key = FixedArray::make(Cooked_key_size, b'\x00')
  let rk = FixedArray::make(Cooked_length, 0U)
  let nr = camlpdf_rijndaelKeySetupEnc(rk, 0, key, start, key_bits)

  // Copy the round keys directly to the cooked key buffer in little-endian format
  // This matches the C implementation which casts the buffer to u32*
  for i = 0; i < Cooked_length; i = i + 1 {
    let bytes = rk[i].to_le_bytes()
    let offset = i * Size_of_u32
    cooked_key[offset] = bytes[0]
    cooked_key[offset + 1] = bytes[1]
    cooked_key[offset + 2] = bytes[2]
    cooked_key[offset + 3] = bytes[3]
  }

  // Store the number of rounds at the designated offset
  cooked_key[Cooked_key_NR_offset] = nr.to_byte()
  cooked_key
}

///|
/// Cook an AES decryption key from bytes
pub fn camlpdf_caml_aes_cook_decrypt_key(
  key : FixedArray[Byte],
  start : Int,
  end : Int,
) -> FixedArray[Byte] {
  let key_bits = (end - start) * 8
  let cooked_key = FixedArray::make(Cooked_key_size, b'\x00')
  let rk = FixedArray::make(Cooked_length, 0U)
  let nr = camlpdf_rijndaelKeySetupDec(rk, 0, key, start, key_bits)

  // Copy the round keys directly to the cooked key buffer in little-endian format
  // This matches the C implementation which casts the buffer to u32*
  for i = 0; i < Cooked_length; i = i + 1 {
    let bytes = rk[i].to_le_bytes()
    let offset = i * Size_of_u32
    cooked_key[offset] = bytes[0]
    cooked_key[offset + 1] = bytes[1]
    cooked_key[offset + 2] = bytes[2]
    cooked_key[offset + 3] = bytes[3]
  }

  // Store the number of rounds at the designated offset
  cooked_key[Cooked_key_NR_offset] = nr.to_byte()
  cooked_key
}

///|
/// Helper to convert Bytes to mutable FixedArray for unsafe operations
fn unsafe_bytes_to_fixed_array_byte(x : Bytes) -> FixedArray[Byte] = "%identity"

///|
/// AES encryption using cooked key and bytes interface
pub fn camlpdf_caml_aes_encrypt(
  ckey : FixedArray[Byte],
  ckey_ofs : Int,
  src : FixedArray[Byte],
  src_ofs : Int,
  dst : FixedArray[Byte],
  dst_ofs : Int,
) -> Unit {
  // Extract the number of rounds from the cooked key
  let nr = ckey[Cooked_key_NR_offset].to_int()

  // Reconstruct the round keys from the cooked key using the helper function
  let rk = fixedarray_uint_of_fixedarray_byte(ckey)

  // Perform the encryption
  camlpdf_rijndaelEncrypt(rk, ckey_ofs, nr, src, src_ofs, dst, dst_ofs)
}

///|
/// AES decryption using cooked key and bytes interface
pub fn camlpdf_caml_aes_decrypt(
  ckey : FixedArray[Byte],
  ckey_ofs : Int,
  src : FixedArray[Byte],
  src_ofs : Int,
  dst : FixedArray[Byte],
  dst_ofs : Int,
) -> Unit {
  // Extract the number of rounds from the cooked key
  let nr = ckey[Cooked_key_NR_offset].to_int()

  // Reconstruct the round keys from the cooked key using the helper function
  let rk = fixedarray_uint_of_fixedarray_byte(ckey)

  // Perform the decryption
  camlpdf_rijndaelDecrypt(rk, ckey_ofs, nr, src, src_ofs, dst, dst_ofs)
}

///|
/// 
/// https://github.com/WebAssembly/design/issues/1569
fn fixedarray_uint_of_fixedarray_byte(
  input : FixedArray[Byte],
) -> FixedArray[UInt] {
  let len = input.length() / Size_of_u32
  let result = FixedArray::make(len, 0U)
  for i = 0; i < len; i = i + 1 {
    let offset = i * Size_of_u32
    let byte0 = input[offset].to_uint()
    let byte1 = input[offset + 1].to_uint()
    let byte2 = input[offset + 2].to_uint()
    let byte3 = input[offset + 3].to_uint()
    // Reconstruct from little-endian format
    result[i] = byte0 | (byte1 << 8) | (byte2 << 16) | (byte3 << 24)
  }
  result
}