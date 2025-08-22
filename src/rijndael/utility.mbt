///|
/// big-endian
fn get_u32(xs : FixedArray[Byte], ofs : Int) -> UInt {
  let b0 = xs[ofs + 0].to_uint()
  let b1 = xs[ofs + 1].to_uint()
  let b2 = xs[ofs + 2].to_uint()
  let b3 = xs[ofs + 3].to_uint()
  return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

///|
/// big-endian
fn set_u32(xs : FixedArray[Byte], ofs : Int, value : UInt) -> Unit {
  let b0 = (value >> 24).to_byte()
  let b1 = (value >> 16).to_byte()
  let b2 = (value >> 8).to_byte()
  let b3 = value.to_byte()
  xs[ofs + 0] = b0
  xs[ofs + 1] = b1
  xs[ofs + 2] = b2
  xs[ofs + 3] = b3
}

///|
test "utility" {
  let buffer = FixedArray::make(8, b'\x00')
  set_u32(buffer, 0, 0x12345678U)
  inspect(
    buffer,
    content="[b'\\x12', b'\\x34', b'\\x56', b'\\x78', b'\\x00', b'\\x00', b'\\x00', b'\\x00']",
  )
  let value = get_u32(buffer, 0)
  inspect(
    value.to_be_bytes(),
    content=(
      #|b"\x12\x34\x56\x78"
    ),
  )
}

///|
const MAXKC : Int = 256 / 32

///|
const MAXKB : Int = 256 / 8

///|
const MAXNR : Int = 14
