///|
/// Helper function to convert bytes to FixedArray[Byte]
fn fixedarray_byte_of_bytes(x : Bytes) -> FixedArray[Byte] = "%identity"

///|
/// Helper function to convert FixedArray[Byte] to bytes
fn bytes_of_fixedarray_byte(x : FixedArray[Byte]) -> Bytes = "%identity"

///|
fn memory_of_fixedarray_byte(x : FixedArray[Byte]) -> @memory.Memory = "%identity"

///|
fn fixedarray_byte_of_memory(x : @memory.Memory) -> FixedArray[Byte] = "%identity"

///|
/// Cook an AES encryption key from bytes
pub fn camlpdf_caml_aes_cook_encrypt_key(
  key : FixedArray[Byte],
  start : Int,
  end : Int,
) -> FixedArray[Byte] {
  let key_bits = (end - start) * 8
  // let cooked_key = FixedArray::make(Cooked_key_size, b'\x00')
  let rk = @memory.Memory::make(Cooked_key_size, 0)
  let nr = camlpdf_rijndaelKeySetupEnc(
    @memory.View::from_memory(rk),
    0,
    memory_of_fixedarray_byte(key),
    start,
    key_bits,
  )
  rk[Cooked_key_NR_offset] = nr.to_byte()
  fixedarray_byte_of_memory(rk)
}

///|
/// Cook an AES decryption key from bytes
pub fn camlpdf_caml_aes_cook_decrypt_key(
  key : FixedArray[Byte],
  start : Int,
  end : Int,
) -> FixedArray[Byte] {
  let key_bits = (end - start) * 8
  // let cooked_key = FixedArray::make(Cooked_key_size, b'\x00')
  let rk = @memory.Memory::make(Cooked_key_size, 0)
  let nr = camlpdf_rijndaelKeySetupDec(
    @memory.View::from_memory(rk),
    0,
    memory_of_fixedarray_byte(key),
    start,
    key_bits,
  )

  // Store the number of rounds at the designated offset
  rk[Cooked_key_NR_offset] = nr.to_byte()
  fixedarray_byte_of_memory(rk)
}

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
  let rk = memory_of_fixedarray_byte(ckey)
  let src = memory_of_fixedarray_byte(src)
  let dst = memory_of_fixedarray_byte(dst)

  // Reconstruct the round keys from the cooked key using the helper function
  // let rk = fixedarray_uint_of_fixedarray_byte(ckey)

  // Perform the encryption
  camlpdf_rijndaelEncrypt(
    @memory.View::from_memory(rk),
    ckey_ofs,
    nr,
    src,
    src_ofs,
    dst,
    dst_ofs,
  )
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
  let rk = memory_of_fixedarray_byte(ckey)
  let src = memory_of_fixedarray_byte(src)
  let dst = memory_of_fixedarray_byte(dst)
  // Perform the decryption
  camlpdf_rijndaelDecrypt(
    @memory.View::from_memory(rk),
    ckey_ofs,
    nr,
    src,
    src_ofs,
    dst,
    dst_ofs,
  )
}
