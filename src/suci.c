/* suci.c
 *
 * Copyright (C) 2022 shahrukh hussain <shahrukh@discreteworks.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "suci_define.h"
#include "suci_test_keys.h"

static int gen_hmac(byte *data_ptr, byte* mac_key, byte* hmac_buffer) {
    Hmac hmac[1];
    int ret = 0;

    ret = wc_HmacInit(hmac, NULL, INVALID_DEVID);
    if (ret == 0) {
        ret = wc_HmacSetKey(hmac, WC_SHA256, mac_key,
                            WC_SHA256_DIGEST_SIZE);
        if (ret == 0)
            ret = wc_HmacUpdate(hmac, data_ptr, 5); //hmac of only the first five bytes
        if (ret == 0)
            ret = wc_HmacUpdate(hmac, NULL, 0);
        if (ret == 0)
            ret = wc_HmacFinal(hmac, hmac_buffer);
        wc_HmacFree(hmac);
    }
    return ret;
}

static int aes_encrypt(byte *data_ptr, byte *supi, int supi_size, byte *enc_key, int enc_key_size, byte * enc_iv) {
    Aes aes;
    int ret = 0;

    ret = wc_AesSetKey(&aes, enc_key, enc_key_size, enc_iv,
                       AES_ENCRYPTION);
    if (ret == 0) {
        // Appends ciphered text to data_ptr
        ret = wc_AesCtrEncrypt(&aes, data_ptr, supi, supi_size);
    }
    return ret;
}

int profile_a(byte *supi, int supi_size, byte *pub_key_buf, byte *eph_pri_key_buf, byte *eph_pub_key_buf, byte *scheme_output) {
    int ret = 0;
    int enc_key_size = 16;

    byte* enc_key = NULL;
    byte* enc_iv = NULL;
    byte* mac_key = NULL;
    byte* scheme_ptr = scheme_output;

    byte iv[ECC_MAX_IV_SIZE];
    byte shared_sec[32] = { 0 };
    byte hmac_buffer[WC_SHA256_DIGEST_SIZE] = { 0 };
    byte bkeys[ECC_BUFSIZE] = { 0 };

    word32 pub_len = 32;
    word32 shared_sec_size = CURVE25519_KEYSIZE;

    curve25519_key pub_key, eph_privKey, eph_pub_key;

    // Import public byte array from SIM
    ret = wc_curve25519_import_public_ex(pub_key_buf, 32, &pub_key, EC25519_LITTLE_ENDIAN);

    if (ret != 0)
        return ret;
    
    ret = wc_curve25519_import_private_ex(eph_pri_key_buf, 32, &eph_privKey, EC25519_LITTLE_ENDIAN);

    if (ret != 0)
        return ret;

    ret = wc_curve25519_import_public_ex(eph_pub_key_buf, 32, &eph_pub_key, EC25519_LITTLE_ENDIAN);

    if (ret != 0)
        return ret;

    // Use home public and UE ephemeral private key to create shared key
    ret = wc_curve25519_shared_secret_ex(&eph_privKey, &pub_key, shared_sec, &shared_sec_size, EC25519_LITTLE_ENDIAN);

    if (ret != 0)
        return ret;

    // ANSI-X9.63-KDF key derivation
    ret = wc_X963_KDF(WC_HASH_TYPE_SHA256, shared_sec, shared_sec_size, eph_pub_key_buf, pub_len, bkeys, 64);

    if (ret != 0)
        return ret;

    memset(iv, 0, ECC_MAX_IV_SIZE);
    enc_key = bkeys;
    enc_iv = enc_key + enc_key_size;
    mac_key = enc_key + ECC_MAX_IV_SIZE + enc_key_size;

    // Appends public key
    ret = wc_curve25519_export_public_ex(&eph_pub_key, scheme_ptr, &pub_len, EC25519_LITTLE_ENDIAN);
    scheme_ptr += pub_len;

    if (ret != 0)
        return ret;

    // AES CTR encrypt
    ret = aes_encrypt(scheme_ptr, supi, supi_size, enc_key, enc_key_size, enc_iv);

    if (ret != 0)
        return ret;

    ret = gen_hmac(scheme_ptr, mac_key, hmac_buffer);

    //  MAC-tag is appended 8 bytes of generated MAC
    scheme_ptr = scheme_ptr + supi_size;
    for (int i = 0; i < 8; i++)
    {
        *scheme_ptr = hmac_buffer[i];
        scheme_ptr++;
    }
    return ret;
}


int profile_b(byte *supi, int supi_size, byte *pub_key_buf, word32 pub_key_buf_sz, byte *eph_pri_key_buf, word32 eph_pri_key_buf_sz,  byte *eph_pub_key_buf, word32 eph_pub_key_buf_sz, byte *scheme_output)
{
    int ret = 0;
    int enc_key_size = 16;

    ecc_key pub_key;
    ecc_key ep_key; // includes both public and private keys

    byte* enc_key = NULL;
    byte* enc_iv = NULL;
    byte* mac_key = NULL;
    byte* scheme_ptr = scheme_output;

    byte shared_sec[ECC_MAXSIZE] = { 0 };
    byte hmac_buffer[WC_SHA256_DIGEST_SIZE] = { 0 };
    byte bkeys[ECC_BUFSIZE] = { 0 };
    byte iv[ECC_MAX_IV_SIZE];

    word32 shared_size = ECC_MAXSIZE;

    WC_RNG  rng;

    ret = wc_InitRng_ex(&rng, NULL, INVALID_DEVID);

    if (ret != 0)
        return ret;

    ret = wc_ecc_import_x963_ex(pub_key_buf, pub_key_buf_sz, &pub_key, ECC_SECP256R1);

    if (ret != 0)
        return ret;

    ret = wc_ecc_set_rng(&pub_key, &rng);

    if (ret != 0)
        return ret;

    ret = wc_ecc_import_private_key_ex(eph_pri_key_buf, eph_pri_key_buf_sz, eph_pub_key_buf, eph_pub_key_buf_sz, &ep_key, ECC_SECP256R1);

    if (ret != 0)
        return ret;

    ret = wc_ecc_set_rng(&ep_key, &rng);

    if (ret != 0)
        return ret;

    ret = wc_ecc_shared_secret(&ep_key, &pub_key, shared_sec, &shared_size);

    if (ret != 0)
        return ret;

    ret = wc_ecc_export_x963_ex(&ep_key, scheme_ptr, &eph_pub_key_buf_sz, 1);

    if (ret != 0)
        return ret;

    scheme_ptr += eph_pub_key_buf_sz;

    // ANSI-X9.63-KDF key derivation
    ret = wc_X963_KDF(WC_HASH_TYPE_SHA256, shared_sec, shared_size, eph_pub_key_buf, eph_pub_key_buf_sz, bkeys, 64);

    if (ret != 0)
        return ret;

    memset(iv, 0, ECC_MAX_IV_SIZE);
    enc_key = bkeys;
    enc_iv = enc_key + enc_key_size;
    mac_key = enc_key + ECC_MAX_IV_SIZE + enc_key_size;

    // AES CTR encrypt
    ret = aes_encrypt(scheme_ptr, supi, supi_size, enc_key, enc_key_size, enc_iv);

    if (ret != 0)
        return ret;

    ret = gen_hmac(scheme_ptr, mac_key, hmac_buffer);

    //  MAC-tag is appended 8 bytes of generated MAC
    scheme_ptr = scheme_ptr + supi_size;
    for (int i = 0; i < 8; i++)
    {
        *scheme_ptr = hmac_buffer[i];
        scheme_ptr++;
    }
    return ret;
}
