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
const MAXKC : Int = 256 / 32

///|
const MAXKB : Int = 256 / 8

///|
const MAXNR : Int = 14

///|
const Size_of_u32 : Int = 4

///|
const Cooked_length : Int = 4 * (MAXNR + 1)

///|
const Cooked_key_NR_offset : Int = Cooked_length * Size_of_u32

///|
const Cooked_key_size : Int = Cooked_key_NR_offset + 1
