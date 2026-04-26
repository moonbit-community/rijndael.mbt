///|
fn[T] unsupported_native_stub() -> T {
  abort("native AES C bindings are only supported on the native target")
}

///|
pub fn camlpdf_caml_aes_cook_encrypt_key(
  _key : FixedArray[Byte],
  _start : Int,
  _end : Int,
) -> FixedArray[Byte] {
  unsupported_native_stub()
}

///|
pub fn camlpdf_caml_aes_cook_decrypt_key(
  _key : FixedArray[Byte],
  _start : Int,
  _end : Int,
) -> FixedArray[Byte] {
  unsupported_native_stub()
}

///|
pub fn camlpdf_caml_aes_encrypt(
  _ckey : FixedArray[Byte],
  _ckey_ofs : Int,
  _src : FixedArray[Byte],
  _src_ofs : Int,
  _dst : FixedArray[Byte],
  _dst_ofs : Int,
) -> Unit {
  unsupported_native_stub()
}

///|
pub fn camlpdf_caml_aes_decrypt(
  _ckey : FixedArray[Byte],
  _ckey_ofs : Int,
  _src : FixedArray[Byte],
  _src_ofs : Int,
  _dst : FixedArray[Byte],
  _dst_ofs : Int,
) -> Unit {
  unsupported_native_stub()
}
