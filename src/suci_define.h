/* suci_define.h
 *
 * Copyright (C) 2022 shahrukh hussain <shahrukh@discreteworks.com>.
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

#ifndef SOME_UNIQUE_NAME
#define SOME_UNIQUE_NAME

// Required defines to enable wolfcrypt features
#define HAVE_CURVE25519
#define HAVE_ECC
#define HAVE_ECC_ENCRYPT
#define WOLFSSL_STATIC_MEMORY
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_COUNTER
#define HAVE_COMP_KEY
#define HAVE_X963_KDF
#define HAVE_CURVE25519_SHARED_SECRET
#define HAVE_CURVE25519_KEY_IMPORT
#define HAVE_ECC_KEY_IMPORT


#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/wc_encrypt.h>

#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/dh.h>

#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ecc.h>


int profile_a(byte *supi, int supi_size, byte *pub_key_buf, byte *eph_pri_key_buf, byte *eph_pub_key_buf, byte *scheme_output);
int profile_b(byte *supi, int supi_size, byte *pub_key_buf, word32 pub_key_buf_sz, byte *eph_pri_key_buf, word32 eph_pri_key_buf_sz,  byte *eph_pub_key_buf, word32 eph_pub_key_buf_sz, byte *scheme_output);

#endif //SUCI_DEFINE_H
