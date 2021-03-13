/* J. P. Just's RSA Tool library
 * Copyright (c) 2005 João Paulo Just Peixoto <just1982@gmail.com>
 * All rights reserved.
 *
 * This file is part of J. P. Just's RSA Tool Library.
 *
 * J. P. Just's RSA Tool Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * J. P. Just's RSA Tool Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with J. P. Just's RSA Tool Library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef _RSATOOL_H
#define _RSATOOL_H

#ifdef __cplusplus
extern "C" {
#endif

#define BASE 36

/* Key structure */
struct rsa_key_st
{
	int size;
	char *n;
	char *e;
	char *d;
};

/* Return a random RSA key given its size in bits */
#ifdef _WIN32_
__declspec(dllexport)
#endif
struct rsa_key_st rsa_genkey(int keysize_int);

/* Return the encrypted message of any lenght using the given key */
#ifdef _WIN32_
__declspec(dllexport)
#endif
char *rsa_encrypt(char *message, struct rsa_key_st key);

/* Return the encrypted message with a limited lenght using the given key.
 * The message limit is the key size.
 */
#ifdef _WIN32_
__declspec(dllexport)
#endif
char *rsa_enc_piece(char *message, struct rsa_key_st key);

/* Return the decrypted message of any lenght using the given key */
#ifdef _WIN32_
__declspec(dllexport)
#endif
char *rsa_decrypt(char *message, struct rsa_key_st key);

/* Return the decrypted message with a limited lenght using the given key.
 * The message limit is the key size.
 */
#ifdef _WIN32_
__declspec(dllexport)
#endif
char *rsa_dec_piece(char *message, struct rsa_key_st key);

/* Convert an octet string into a non-negative integer */
#ifdef _WIN32_
__declspec(dllexport)
#endif
char *rsa_os2i(unsigned char *message);

/* Convert a non-negative integer into a octet string */
#ifdef _WIN32_
__declspec(dllexport)
#endif
char *rsa_i2os(char *number, int msg_size);

#ifdef __cplusplus
}
#endif
#endif
