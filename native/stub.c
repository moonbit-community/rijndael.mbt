#include "rijndael-alg-fst.h"
#include <moonbit.h>
#include <stdint.h>

#define Cooked_key_NR_offset ((4 * (MAXNR + 1)) * sizeof(u32))
#define Cooked_key_size (Cooked_key_NR_offset + 1)

MOONBIT_EXPORT moonbit_bytes_t
camlpdf_caml_aes_cook_encrypt_key(moonbit_bytes_t key) {
  size_t ckey_len = Cooked_key_size;
  moonbit_bytes_t ckey = moonbit_make_bytes(ckey_len, 0);
  size_t key_len = Moonbit_array_length(key);
  int nr =
      camlpdf_rijndaelKeySetupEnc((u32 *)ckey, (const u8 *)key, 8 * key_len);
  ckey[Cooked_key_NR_offset] = nr;
  return ckey;
}

MOONBIT_EXPORT moonbit_bytes_t
camlpdf_caml_aes_cook_decrypt_key(moonbit_bytes_t key) {
  size_t ckey_len = Cooked_key_size;
  moonbit_bytes_t ckey = moonbit_make_bytes(ckey_len, 0);
  size_t key_len = Moonbit_array_length(key);
  int nr =
      camlpdf_rijndaelKeySetupDec((u32 *)ckey, (const u8 *)key, 8 * key_len);
  ckey[Cooked_key_NR_offset] = nr;
  return ckey;
}

MOONBIT_EXPORT void camlpdf_caml_aes_encrypt(moonbit_bytes_t ckey,
                                             moonbit_bytes_t src,
                                             int32_t src_ofs,
                                             moonbit_bytes_t dst,
                                             int32_t dst_ofs) {
  camlpdf_rijndaelEncrypt((const u32 *)ckey, ckey[Cooked_key_NR_offset],
                          (const u8 *)src + src_ofs, (u8 *)dst + dst_ofs);
}
MOONBIT_EXPORT void camlpdf_caml_aes_decrypt(moonbit_bytes_t ckey,
                                             moonbit_bytes_t src,
                                             int32_t src_ofs,
                                             moonbit_bytes_t dst,
                                             int32_t dst_ofs) {
  camlpdf_rijndaelDecrypt((const u32 *)ckey, ckey[Cooked_key_NR_offset],
                          (const u8 *)src + src_ofs, (u8 *)dst + dst_ofs);
}