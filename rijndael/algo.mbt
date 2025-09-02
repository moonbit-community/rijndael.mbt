///|
/// 
/// Expand the cipher key into the encryption key schedule.
/// 
/// @return	the number of rounds for the given cipher key size.
/// 
fn camlpdf_rijndaelKeySetupEnc(
  rk : FixedArray[UInt],
  rk_ofs : Int,
  cipherKey : FixedArray[Byte],
  cipherKey_ofs : Int,
  keyBits : Int,
) -> Int {
  let mut i = 0
  let mut offset = rk_ofs
  let mut temp : UInt = 0
  rk[offset + 0] = get_u32(cipherKey, cipherKey_ofs + 0)
  rk[offset + 1] = get_u32(cipherKey, cipherKey_ofs + 4)
  rk[offset + 2] = get_u32(cipherKey, cipherKey_ofs + 8)
  rk[offset + 3] = get_u32(cipherKey, cipherKey_ofs + 12)
  if keyBits == 128 {
    while true {
      temp = rk[offset + 3]
      rk[offset + 4] = rk[offset + 0] ^
        (te4[((temp >> 16) & 0xff).reinterpret_as_int()] & 0xff000000) ^
        (te4[((temp >> 8) & 0xff).reinterpret_as_int()] & 0x00ff0000) ^
        (te4[(temp & 0xff).reinterpret_as_int()] & 0x0000ff00) ^
        (te4[(temp >> 24).reinterpret_as_int()] & 0x000000ff) ^
        rcon[i]
      rk[offset + 5] = rk[offset + 1] ^ rk[offset + 4]
      rk[offset + 6] = rk[offset + 2] ^ rk[offset + 5]
      rk[offset + 7] = rk[offset + 3] ^ rk[offset + 6]
      i += 1
      if i == 10 {
        return 10
      }
      offset += 4
    }
  }
  rk[offset + 4] = get_u32(cipherKey, 16)
  rk[offset + 5] = get_u32(cipherKey, 20)
  if keyBits == 192 {
    while true {
      temp = rk[offset + 5]
      rk[offset + 6] = rk[offset + 0] ^
        (te4[((temp >> 16) & 0xff).reinterpret_as_int()] & 0xff000000) ^
        (te4[((temp >> 8) & 0xff).reinterpret_as_int()] & 0x00ff0000) ^
        (te4[(temp & 0xff).reinterpret_as_int()] & 0x0000ff00) ^
        (te4[(temp >> 24).reinterpret_as_int()] & 0x000000ff) ^
        rcon[i]
      rk[offset + 7] = rk[offset + 1] ^ rk[offset + 6]
      rk[offset + 8] = rk[offset + 2] ^ rk[offset + 7]
      rk[offset + 9] = rk[offset + 3] ^ rk[offset + 8]
      i += 1
      if i == 8 {
        return 12
      }
      rk[offset + 10] = rk[offset + 4] ^ rk[offset + 9]
      rk[offset + 11] = rk[offset + 5] ^ rk[offset + 10]
      offset += 6
    }
  }
  rk[offset + 6] = get_u32(cipherKey, 24)
  rk[offset + 7] = get_u32(cipherKey, 28)
  if keyBits == 256 {
    while true {
      temp = rk[offset + 7]
      rk[offset + 8] = rk[offset + 0] ^
        (te4[((temp >> 16) & 0xff).reinterpret_as_int()] & 0xff000000) ^
        (te4[((temp >> 8) & 0xff).reinterpret_as_int()] & 0x00ff0000) ^
        (te4[(temp & 0xff).reinterpret_as_int()] & 0x0000ff00) ^
        (te4[(temp >> 24).reinterpret_as_int()] & 0x000000ff) ^
        rcon[i]
      rk[offset + 9] = rk[offset + 1] ^ rk[offset + 8]
      rk[offset + 10] = rk[offset + 2] ^ rk[offset + 9]
      rk[offset + 11] = rk[offset + 3] ^ rk[offset + 10]
      i += 1
      if i == 7 {
        return 14
      }
      temp = rk[offset + 11]
      rk[offset + 12] = rk[offset + 4] ^
        (te4[(temp >> 24).reinterpret_as_int()] & 0xff000000) ^
        (te4[((temp >> 16) & 0xff).reinterpret_as_int()] & 0x00ff0000) ^
        (te4[((temp >> 8) & 0xff).reinterpret_as_int()] & 0x0000ff00) ^
        (te4[(temp & 0xff).reinterpret_as_int()] & 0x000000ff)
      rk[offset + 13] = rk[offset + 5] ^ rk[offset + 12]
      rk[offset + 14] = rk[offset + 6] ^ rk[offset + 13]
      rk[offset + 15] = rk[offset + 7] ^ rk[offset + 14]
      offset += 8
    }
  }
  return 0
}

///|
fnalias UInt::reinterpret_as_int as idx

///|
/// 
/// Expand the cipher key into the decryption key schedule.
/// 
/// @return	the number of rounds for the given cipher key size.
/// 
fn camlpdf_rijndaelKeySetupDec(
  rk : FixedArray[UInt],
  rk_ofs : Int,
  cipherKey : FixedArray[Byte],
  cipherKey_ofs : Int,
  keyBits : Int,
) -> Int {
  // expand the cipher key
  let nr = camlpdf_rijndaelKeySetupEnc(
    rk, rk_ofs, cipherKey, cipherKey_ofs, keyBits,
  )

  // invert the order of the round keys
  // equivalent to `rk.rev_inplace()`
  for i = 0, j = 4 * nr; i < j; i = i + 4, j = j - 4 {
    // unroll loop
    rk.swap(i, j)
    rk.swap(i + 1, j + 1)
    rk.swap(i + 2, j + 2)
    rk.swap(i + 3, j + 3)
  }
  // apply the inverse MixColumn transform to all round keys but the first and the last

  let mut offset = 0
  for i in 1..<nr {
    offset += 4
    // unroll loop
    rk[offset + 0] = td0[idx(te4[idx(rk[offset + 0] >> 24)] & 0xff)] ^
      td1[idx(te4[idx((rk[offset + 0] >> 16) & 0xff)] & 0xff)] ^
      td2[idx(te4[idx((rk[offset + 0] >> 8) & 0xff)] & 0xff)] ^
      td3[idx(te4[idx(rk[offset + 0] & 0xff)] & 0xff)]
    rk[offset + 1] = td0[idx(te4[idx(rk[offset + 1] >> 24)] & 0xff)] ^
      td1[idx(te4[idx((rk[offset + 1] >> 16) & 0xff)] & 0xff)] ^
      td2[idx(te4[idx((rk[offset + 1] >> 8) & 0xff)] & 0xff)] ^
      td3[idx(te4[idx(rk[offset + 1] & 0xff)] & 0xff)]
    rk[offset + 2] = td0[idx(te4[idx(rk[offset + 2] >> 24)] & 0xff)] ^
      td1[idx(te4[idx((rk[offset + 2] >> 16) & 0xff)] & 0xff)] ^
      td2[idx(te4[idx((rk[offset + 2] >> 8) & 0xff)] & 0xff)] ^
      td3[idx(te4[idx(rk[offset + 2] & 0xff)] & 0xff)]
    rk[offset + 3] = td0[idx(te4[idx(rk[offset + 3] >> 24)] & 0xff)] ^
      td1[idx(te4[idx((rk[offset + 3] >> 16) & 0xff)] & 0xff)] ^
      td2[idx(te4[idx((rk[offset + 3] >> 8) & 0xff)] & 0xff)] ^
      td3[idx(te4[idx(rk[offset + 3] & 0xff)] & 0xff)]
  }
  nr
}

///|
fn camlpdf_rijndaelEncrypt(
  rk : FixedArray[UInt],
  rk_ofs : Int,
  nr : Int,
  pt : FixedArray[Byte],
  pt_ofs : Int,
  ct : FixedArray[Byte],
  ct_ofs : Int,
) -> Unit {
  let mut offset = rk_ofs
  let mut s0 : UInt = 0
  let mut s1 : UInt = 0
  let mut s2 : UInt = 0
  let mut s3 : UInt = 0
  let mut t0 : UInt = 0
  let mut t1 : UInt = 0
  let mut t2 : UInt = 0
  let mut t3 : UInt = 0
  /// map byte array block to cipher state and add initial round key

  s0 = get_u32(pt, pt_ofs + 0) ^ rk[offset + 0]
  s1 = get_u32(pt, pt_ofs + 4) ^ rk[offset + 1]
  s2 = get_u32(pt, pt_ofs + 8) ^ rk[offset + 2]
  s3 = get_u32(pt, pt_ofs + 12) ^ rk[offset + 3]

  // nr -1 full rounds 
  let mut r = nr >> 1
  while true {
    t0 = te0[idx(s0 >> 24)] ^
      te1[idx((s1 >> 16) & 0xff)] ^
      te2[idx((s2 >> 8) & 0xff)] ^
      te3[idx(s3 & 0xff)] ^
      rk[offset + 4]
    t1 = te0[idx(s1 >> 24)] ^
      te1[idx((s2 >> 16) & 0xff)] ^
      te2[idx((s3 >> 8) & 0xff)] ^
      te3[idx(s0 & 0xff)] ^
      rk[offset + 5]
    t2 = te0[idx(s2 >> 24)] ^
      te1[idx((s3 >> 16) & 0xff)] ^
      te2[idx((s0 >> 8) & 0xff)] ^
      te3[idx(s1 & 0xff)] ^
      rk[offset + 6]
    t3 = te0[idx(s3 >> 24)] ^
      te1[idx((s0 >> 16) & 0xff)] ^
      te2[idx((s1 >> 8) & 0xff)] ^
      te3[idx(s2 & 0xff)] ^
      rk[offset + 7]
    offset += 8
    r -= 1
    if r == 0 {
      break
    }
    s0 = te0[idx(t0 >> 24)] ^
      te1[idx((t1 >> 16) & 0xff)] ^
      te2[idx((t2 >> 8) & 0xff)] ^
      te3[idx(t3 & 0xff)] ^
      rk[offset + 0]
    s1 = te0[idx(t1 >> 24)] ^
      te1[idx((t2 >> 16) & 0xff)] ^
      te2[idx((t3 >> 8) & 0xff)] ^
      te3[idx(t0 & 0xff)] ^
      rk[offset + 1]
    s2 = te0[idx(t2 >> 24)] ^
      te1[idx((t3 >> 16) & 0xff)] ^
      te2[idx((t0 >> 8) & 0xff)] ^
      te3[idx(t1 & 0xff)] ^
      rk[offset + 2]
    s3 = te0[idx(t3 >> 24)] ^
      te1[idx((t0 >> 16) & 0xff)] ^
      te2[idx((t1 >> 8) & 0xff)] ^
      te3[idx(t2 & 0xff)] ^
      rk[offset + 3]
  }
  // apply last round and map cipher state to byte array block

  s0 = (te4[idx(t0 >> 24)] & 0xff000000) ^
    (te4[idx((t1 >> 16) & 0xff)] & 0x00ff0000) ^
    (te4[idx((t2 >> 8) & 0xff)] & 0x0000ff00) ^
    (te4[idx(t3 & 0xff)] & 0x000000ff) ^
    rk[offset + 0]
  set_u32(ct, ct_ofs + 0, s0)
  s1 = (te4[idx(t1 >> 24)] & 0xff000000) ^
    (te4[idx((t2 >> 16) & 0xff)] & 0x00ff0000) ^
    (te4[idx((t3 >> 8) & 0xff)] & 0x0000ff00) ^
    (te4[idx(t0 & 0xff)] & 0x000000ff) ^
    rk[offset + 1]
  set_u32(ct, ct_ofs + 4, s1)
  s2 = (te4[idx(t2 >> 24)] & 0xff000000) ^
    (te4[idx((t3 >> 16) & 0xff)] & 0x00ff0000) ^
    (te4[idx((t0 >> 8) & 0xff)] & 0x0000ff00) ^
    (te4[idx(t1 & 0xff)] & 0x000000ff) ^
    rk[offset + 2]
  set_u32(ct, ct_ofs + 8, s2)
  s3 = (te4[idx(t3 >> 24)] & 0xff000000) ^
    (te4[idx((t0 >> 16) & 0xff)] & 0x00ff0000) ^
    (te4[idx((t1 >> 8) & 0xff)] & 0x0000ff00) ^
    (te4[idx(t2 & 0xff)] & 0x000000ff) ^
    rk[offset + 3]
  set_u32(ct, ct_ofs + 12, s3)
}

///|
fn camlpdf_rijndaelDecrypt(
  rk : FixedArray[UInt],
  rk_ofs : Int,
  nr : Int,
  ct : FixedArray[Byte],
  ct_ofs : Int,
  pt : FixedArray[Byte],
  pt_ofs : Int,
) -> Unit {
  let mut offset = rk_ofs
  let mut s0 : UInt = 0
  let mut s1 : UInt = 0
  let mut s2 : UInt = 0
  let mut s3 : UInt = 0
  let mut t0 : UInt = 0
  let mut t1 : UInt = 0
  let mut t2 : UInt = 0
  let mut t3 : UInt = 0

  // map byte array block to cipher state
  // and add initial round key
  //

  s0 = get_u32(ct, ct_ofs + 0) ^ rk[offset + 0]
  s1 = get_u32(ct, ct_ofs + 4) ^ rk[offset + 1]
  s2 = get_u32(ct, ct_ofs + 8) ^ rk[offset + 2]
  s3 = get_u32(ct, ct_ofs + 12) ^ rk[offset + 3]
  let mut r = nr >> 1
  while true {
    t0 = td0[idx(s0 >> 24)] ^
      td1[idx(s3 >> 16) & 0xff] ^
      td2[idx(s2 >> 8) & 0xff] ^
      td3[idx(s1) & 0xff] ^
      rk[offset + 4]
    t1 = td0[idx(s1 >> 24)] ^
      td1[idx(s0 >> 16) & 0xff] ^
      td2[idx(s3 >> 8) & 0xff] ^
      td3[idx(s2) & 0xff] ^
      rk[offset + 5]
    t2 = td0[idx(s2 >> 24)] ^
      td1[idx(s1 >> 16) & 0xff] ^
      td2[idx(s0 >> 8) & 0xff] ^
      td3[idx(s3) & 0xff] ^
      rk[offset + 6]
    t3 = td0[idx(s3 >> 24)] ^
      td1[idx(s2 >> 16) & 0xff] ^
      td2[idx(s1 >> 8) & 0xff] ^
      td3[idx(s0) & 0xff] ^
      rk[offset + 7]
    offset += 8
    r -= 1
    if r == 0 {
      break
    }
    s0 = td0[idx(t0 >> 24)] ^
      td1[idx(t3 >> 16) & 0xff] ^
      td2[idx(t2 >> 8) & 0xff] ^
      td3[idx(t1) & 0xff] ^
      rk[offset + 0]
    s1 = td0[idx(t1 >> 24)] ^
      td1[idx(t0 >> 16) & 0xff] ^
      td2[idx(t3 >> 8) & 0xff] ^
      td3[idx(t2) & 0xff] ^
      rk[offset + 1]
    s2 = td0[idx(t2 >> 24)] ^
      td1[idx(t1 >> 16) & 0xff] ^
      td2[idx(t0 >> 8) & 0xff] ^
      td3[idx(t3) & 0xff] ^
      rk[offset + 2]
    s3 = td0[idx(t3 >> 24)] ^
      td1[idx(t2 >> 16) & 0xff] ^
      td2[idx(t1 >> 8) & 0xff] ^
      td3[idx(t0) & 0xff] ^
      rk[offset + 3]
  }
  s0 = (td4[idx(t0 >> 24)] & 0xff000000) ^
    (td4[idx((t3 >> 16) & 0xff)] & 0x00ff0000) ^
    (td4[idx((t2 >> 8) & 0xff)] & 0x0000ff00) ^
    (td4[idx(t1 & 0xff)] & 0x000000ff) ^
    rk[offset + 0]
  set_u32(pt, pt_ofs + 0, s0)
  s1 = (td4[idx(t1 >> 24)] & 0xff000000) ^
    (td4[idx((t0 >> 16) & 0xff)] & 0x00ff0000) ^
    (td4[idx((t3 >> 8) & 0xff)] & 0x0000ff00) ^
    (td4[idx(t2 & 0xff)] & 0x000000ff) ^
    rk[offset + 1]
  set_u32(pt, pt_ofs + 4, s1)
  s2 = (td4[idx(t2 >> 24)] & 0xff000000) ^
    (td4[idx((t1 >> 16) & 0xff)] & 0x00ff0000) ^
    (td4[idx((t0 >> 8) & 0xff)] & 0x0000ff00) ^
    (td4[idx(t3 & 0xff)] & 0x000000ff) ^
    rk[offset + 2]
  set_u32(pt, pt_ofs + 8, s2)
  s3 = (td4[idx(t3 >> 24)] & 0xff000000) ^
    (td4[idx((t2 >> 16) & 0xff)] & 0x00ff0000) ^
    (td4[idx((t1 >> 8) & 0xff)] & 0x0000ff00) ^
    (td4[idx(t0 & 0xff)] & 0x000000ff) ^
    rk[offset + 3]
  set_u32(pt, pt_ofs + 12, s3)
}
