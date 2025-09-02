///|
test "compatibility with random data" {
  // Test with random-like plaintext similar to native package
  let key : Bytes = "0123456789ABCDEF"

  // Manually create some "random" data for deterministic test
  let random_plaintext = FixedArray::make(16, b'\x00')
  random_plaintext[0] = b'\x03'
  random_plaintext[1] = b'\x91'
  random_plaintext[2] = b'\xec'
  random_plaintext[3] = b'\x01'
  random_plaintext[4] = b'\x70'
  random_plaintext[5] = b'\x77'
  random_plaintext[6] = b'\x38'
  random_plaintext[7] = b'\xe0'
  random_plaintext[8] = b'\xb0'
  random_plaintext[9] = b'\xac'
  random_plaintext[10] = b'\xa7'
  random_plaintext[11] = b'\x3b'
  random_plaintext[12] = b'\xac'
  random_plaintext[13] = b'\x22'
  random_plaintext[14] = b'\x53'
  random_plaintext[15] = b'\x19'
  inspect(
    bytes_of_fixedarray_byte(random_plaintext),
    content=(
      #|b"\x03\x91\xec\x01\x70\x77\x38\xe0\xb0\xac\xa7\x3b\xac\x22\x53\x19"
    ),
  )
  let plaintext_bytes = bytes_of_fixedarray_byte(random_plaintext)
  aes_test_driver(key, plaintext_bytes)
}

///|
test "key schedule round counts" {
  // Test that different key sizes produce correct round counts
  let key_128 = b"0123456789ABCDEF"
  let key_192 = b"0123456789ABCDEF01234567"
  let key_256 = b"0123456789ABCDEF0123456789ABCDEF"

  // Convert to FixedArray[Byte] and get lengths
  let key_128_fa = fixedarray_byte_of_bytes(key_128)
  let key_192_fa = fixedarray_byte_of_bytes(key_192)
  let key_256_fa = fixedarray_byte_of_bytes(key_256)

  // Test encrypt key setup
  let enc_128 = camlpdf_caml_aes_cook_encrypt_key(
    key_128_fa,
    0,
    key_128_fa.length(),
  )
  let enc_192 = camlpdf_caml_aes_cook_encrypt_key(
    key_192_fa,
    0,
    key_192_fa.length(),
  )
  let enc_256 = camlpdf_caml_aes_cook_encrypt_key(
    key_256_fa,
    0,
    key_256_fa.length(),
  )

  // Check round count (last byte)
  inspect(enc_128[Cooked_key_NR_offset].to_int(), content="10") // 128-bit: 10 rounds
  inspect(enc_192[Cooked_key_NR_offset].to_int(), content="12") // 192-bit: 12 rounds
  inspect(enc_256[Cooked_key_NR_offset].to_int(), content="14") // 256-bit: 14 rounds

  // Test decrypt key setup
  let dec_128 = camlpdf_caml_aes_cook_decrypt_key(
    key_128_fa,
    0,
    key_128_fa.length(),
  )
  let dec_192 = camlpdf_caml_aes_cook_decrypt_key(
    key_192_fa,
    0,
    key_192_fa.length(),
  )
  let dec_256 = camlpdf_caml_aes_cook_decrypt_key(
    key_256_fa,
    0,
    key_256_fa.length(),
  )

  // Check round count (last byte)
  inspect(dec_128[Cooked_key_NR_offset].to_int(), content="10") // 128-bit: 10 rounds
  inspect(dec_192[Cooked_key_NR_offset].to_int(), content="12") // 192-bit: 12 rounds
  inspect(dec_256[Cooked_key_NR_offset].to_int(), content="14") // 256-bit: 14 rounds
}

///|
test "multiple block encryption/decryption" {
  let key : Bytes = "0123456789ABCDEF"
  let key_fa = fixedarray_byte_of_bytes(key)
  let encrypt_cooked = camlpdf_caml_aes_cook_encrypt_key(
    key_fa,
    0,
    key_fa.length(),
  )
  let decrypt_cooked = camlpdf_caml_aes_cook_decrypt_key(
    key_fa,
    0,
    key_fa.length(),
  )

  // Test multiple 16-byte blocks
  let plaintext1 : Bytes = "Time is precious"
  let plaintext2 : Bytes = "MoonBit is great"
  let plaintext3 : Bytes = "Rijndael AES enc"
  let ciphertext = FixedArray::make(48, b'\x00') // 3 blocks
  let decrypted = FixedArray::make(48, b'\x00')

  // Convert plaintexts to FixedArray[Byte]
  let plaintext1_fa = fixedarray_byte_of_bytes(plaintext1)
  let plaintext2_fa = fixedarray_byte_of_bytes(plaintext2)
  let plaintext3_fa = fixedarray_byte_of_bytes(plaintext3)

  // Encrypt all three blocks
  camlpdf_caml_aes_encrypt(encrypt_cooked, 0, plaintext1_fa, 0, ciphertext, 0)
  camlpdf_caml_aes_encrypt(encrypt_cooked, 0, plaintext2_fa, 0, ciphertext, 16)
  camlpdf_caml_aes_encrypt(encrypt_cooked, 0, plaintext3_fa, 0, ciphertext, 32)

  // Decrypt all three blocks
  camlpdf_caml_aes_decrypt(decrypt_cooked, 0, ciphertext, 0, decrypted, 0)
  camlpdf_caml_aes_decrypt(decrypt_cooked, 0, ciphertext, 16, decrypted, 16)
  camlpdf_caml_aes_decrypt(decrypt_cooked, 0, ciphertext, 32, decrypted, 32)

  // Verify each block - convert back to bytes for comparison
  let decrypted_bytes = bytes_of_fixedarray_byte(decrypted)
  assert_eq(plaintext1, decrypted_bytes[0:16].to_bytes())
  assert_eq(plaintext2, decrypted_bytes[16:32].to_bytes())
  assert_eq(plaintext3, decrypted_bytes[32:48].to_bytes())
}

///|
test "offset parameter usage" {
  let key : Bytes = "0123456789ABCDEF"
  let plaintext : Bytes = "Time is precious"

  // Test using the new API directly with offsets
  let key_array = fixedarray_byte_of_bytes(key)
  let plaintext_array = fixedarray_byte_of_bytes(plaintext)
  let ciphertext_array = FixedArray::make(16, b'\x00')
  let decrypted_array = FixedArray::make(16, b'\x00')

  // Setup keys with offset 0
  let ekey = FixedArray::make(Cooked_length, 0U)
  let dkey = FixedArray::make(Cooked_length, 0U)
  let nr_enc = camlpdf_rijndaelKeySetupEnc(ekey, 0, key_array, 0, 128)
  let nr_dec = camlpdf_rijndaelKeySetupDec(dkey, 0, key_array, 0, 128)

  // Encrypt and decrypt using offset-based API
  camlpdf_rijndaelEncrypt(
    ekey, 0, nr_enc, plaintext_array, 0, ciphertext_array, 0,
  )
  camlpdf_rijndaelDecrypt(
    dkey, 0, nr_dec, ciphertext_array, 0, decrypted_array, 0,
  )

  // Verify results
  assert_eq(plaintext_array, decrypted_array)
  inspect(nr_enc, content="10") // 128-bit key should have 10 rounds
  inspect(nr_dec, content="10")
}
