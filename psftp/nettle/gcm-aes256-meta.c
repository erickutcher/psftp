/* gcm-aes256-meta.c

   Copyright (C) 2014 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>

#include "nettle-meta.h"

#include "gcm.h"

static nettle_set_key_func gcm_aes256_set_nonce_wrapper;
static void
gcm_aes256_set_nonce_wrapper (void *ctx, const uint8_t *nonce)
{
  gcm_aes256_set_iv ((gcm_aes256_ctx *)ctx, GCM_IV_SIZE, nonce);
}

const struct nettle_aead nettle_gcm_aes256 =
  { "gcm_aes256", sizeof(struct gcm_aes256_ctx),
    GCM_BLOCK_SIZE, AES256_KEY_SIZE,
    GCM_IV_SIZE, GCM_DIGEST_SIZE,
    (nettle_set_key_func *) gcm_aes256_set_key,
    (nettle_set_key_func *) gcm_aes256_set_key,
    gcm_aes256_set_nonce_wrapper,
    (nettle_hash_update_func *) gcm_aes256_update,
    (nettle_crypt_func *) gcm_aes256_encrypt,
    (nettle_crypt_func *) gcm_aes256_decrypt,
    (nettle_hash_digest_func *) gcm_aes256_digest,
  };
