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

#include "rsatool.h"
#include <gmp.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#ifdef _LINUX_
# include <sys/time.h>
#endif
#ifdef _WIN32_
# include <time.h>
#endif

/* Return a random RSA key given its size in bits */
#ifdef _WIN32_
__declspec(dllexport)
#endif
struct rsa_key_st rsa_genkey(int keysize_int)
{
#ifdef _LINUX_
	struct timeval tv;
#endif
#ifdef _WIN32_
	time_t tv;
#endif

	struct rsa_key_st res_key;
	mpz_t keysize, p, q, n, phi, e, d;
	mpz_t i, aux;
	gmp_randstate_t rstate;

	mpz_init(keysize);
	mpz_init(p);
	mpz_init(q);
	mpz_init(n);
	mpz_init(phi);
	mpz_init(e);
	mpz_init(d);
	mpz_init(i);
	mpz_init(aux);

	mpz_set_ui(keysize, keysize_int);
	gmp_randinit_default(rstate);

#ifdef _LINUX_
	gettimeofday(&tv, NULL);
	gmp_randseed_ui(rstate, tv.tv_usec);
#endif
#ifdef _WIN32_
	time(&tv);
	gmp_randseed_ui(rstate, tv);
#endif

	do
	{
		/* Generate p */
		do
		{
			mpz_urandomb(p, rstate, keysize_int / 2);
		} while (mpz_probab_prime_p(p, 10) == 0);	/* Repeat the loop until we get a prime number */

		/* Do the same for q */
		do
		{
			mpz_urandomb(q, rstate, keysize_int / 2);
		} while ((mpz_probab_prime_p(q, 10) == 0) || (mpz_cmp(p, q) == 0));

		if (mpz_cmp(p, q) < 0)
			mpz_swap(p, q);

		/* Some other variables... */
		mpz_mul(n, p, q);
		mpz_sub_ui(p, p, 1);
		mpz_sub_ui(q, q, 1);
		mpz_mul(phi, p, q);

		/* Check if n and phi have the correct size */
		if ((mpz_sizeinbase(n, 2) != keysize_int) || (mpz_sizeinbase(phi, 2) != keysize_int))
			continue;

		/* Compute e */
		mpz_set_ui(e, 0);
		for (mpz_sub_ui(i, phi, 2); mpz_cmp_ui(i, 2) > 0; mpz_sub_ui(i, i, 1))
		{
			mpz_gcd(aux, i, phi);
			if (mpz_cmp_ui(aux, 1) == 0)
			{
				mpz_set(e, i);
				break;
			}
		}
		/* We couldn't compute 'e' with our current n and phi, so, try again */
		if (mpz_cmp_ui(e, 0) == 0)
			continue;

		/* Compute d */
		mpz_set_ui(d, 0);
		if (mpz_invert(aux, e, phi) == 0)
			continue;
		mpz_set(d, aux);
	} while (mpz_cmp_ui(d, 0) == 0);

	/* Return the results */
	res_key.size = keysize_int;
	res_key.n = mpz_get_str(NULL, BASE, n);
	res_key.e = mpz_get_str(NULL, BASE, e);
	res_key.d = mpz_get_str(NULL, BASE, d);

	mpz_clear(keysize);
	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(n);
	mpz_clear(phi);
	mpz_clear(e);
	mpz_clear(d);
	mpz_clear(i);
	mpz_clear(aux);
	gmp_randclear(rstate);

	return res_key;
}

/* Return the encrypted message of any lenght using the given key */
#ifdef _WIN32_
__declspec(dllexport)
#endif
char *rsa_encrypt(char *message, struct rsa_key_st key)
{
	mpz_t key_n;
	int i, c_len, p_len, pieces;
	char *res, *res_aux, *msg_aux;

	/* The same trivial initialization... */
	mpz_init(key_n);
	mpz_set_str(key_n, key.n, BASE);

	/* Some useful things to calculate */
	c_len = mpz_sizeinbase(key_n, BASE);
	p_len = key.size / 8;
	pieces = strlen(message) / p_len + 1;
	if (strlen(message) % p_len == 0)
		pieces--;

	mpz_clear(key_n);

	/* Memory allocation */
	res = (char *)calloc(pieces * c_len + 1, sizeof(char));
	msg_aux = (char *)calloc(p_len + 1, sizeof(char));

	if ((res == NULL) || (msg_aux == NULL))	/* Error trying to allocate memory */
		return NULL;

	/* We need to encrypt every piece of the message separately */
	for (i = 0; i < pieces; i++)
	{
		strncpy(msg_aux, message + (i * p_len), p_len);
		res_aux = rsa_enc_piece(msg_aux, key);

		strcpy(res + (i * c_len), res_aux);

		free(res_aux);
	}

	free(msg_aux);
	return res;
}

/* Return the encrypted message with a limited lenght using the given key.
 * The message limit is the key size.
 */
#ifdef _WIN32_
__declspec(dllexport)
#endif
char *rsa_enc_piece(char *message, struct rsa_key_st key)
{
	mpz_t c, m, key_n, key_e;
	char *res, *res_aux, *number;
	int m_len = strlen(message);
	int i;

	/* Check for invalid messages */
	if (m_len < 1)
		return NULL;
	else if (m_len > key.size / 8)
		m_len = key.size / 8;

	/* Again, that initialization... */
	mpz_init(c);
	mpz_init(m);
	mpz_init(key_n);
	mpz_init(key_e);

	/* Begin the encryption process */
	number = rsa_os2i((unsigned char *)message);

	mpz_set_str(m, number, 10);
	mpz_set_str(key_n, key.n, BASE);
	mpz_set_str(key_e, key.e, BASE);

	mpz_powm(c, m, key_e, key_n);

	res = mpz_get_str(NULL, BASE, c);

	/* Insert zeroes in the beginning */
	if (strlen(res) < strlen(key.n))
	{
		res_aux = (char *)calloc(strlen(key.n) + 1, sizeof(char));
		res = (char *)realloc(res, (strlen(key.n) + 1) * sizeof(char));

		strcpy(res_aux + (strlen(key.n) - strlen(res)), res);

		for (i = 0; i < (strlen(key.n) - strlen(res)); i++)
			res_aux[i] = '0';

		strcpy(res, res_aux);
		free(res_aux);
	}

	/* Clear everything */
	mpz_clear(c);
	mpz_clear(m);
	mpz_clear(key_n);
	mpz_clear(key_e);

	free(number);

	return res;
}

/* Return the decrypted message of any lenght using the given key */
#ifdef _WIN32_
__declspec(dllexport)
#endif
char *rsa_decrypt(char *message, struct rsa_key_st key)
{
	char *res, *msg, *msg_aux;
	int i, p_len, pieces, m_len;

	/* Some useful things to calculate */
	p_len = strlen(key.n);
	m_len = key.size / 8;
	pieces = strlen(message) / p_len;

	/* Memory allocation */
	res = (char *)calloc(pieces * m_len + 1, sizeof(char));
	msg_aux = (char *)calloc(p_len + 1, sizeof(char));

	/* We must decrypt every piece of the message separately... */
	for (i = 0; i < pieces; i++)
	{
		strncpy(msg_aux, message + (i * p_len), p_len);

		msg = rsa_dec_piece(msg_aux, key);
		strcpy(res + (i * m_len), msg);

		free(msg);
	}

	free(msg_aux);

	return res;
}

/* Return the decrypted message with a limited lenght using the given key.
 * The message limit is the key size.
 */
#ifdef _WIN32_
__declspec(dllexport)
#endif
char *rsa_dec_piece(char *message, struct rsa_key_st key)
{
	mpz_t c, m, key_n, key_d;
	char *res, *msg;

	/* We don't want invalid messages */
	if (strlen(message) != strlen(key.n))
		return NULL;
	/* Once again, that trivial initialization... */
	mpz_init(c);
	mpz_init(m);
	mpz_init(key_n);
	mpz_init(key_d);

	/* Now we begin the decryption process */
	mpz_set_str(c, message, BASE);
	mpz_set_str(key_n, key.n, BASE);
	mpz_set_str(key_d, key.d, BASE);

	mpz_powm(m, c, key_d, key_n);

	msg = mpz_get_str(NULL, 10, m);
	res = rsa_i2os(msg, strlen(msg));

	/* Clearing everything */
	mpz_clear(c);
	mpz_clear(m);
	mpz_clear(key_n);
	mpz_clear(key_d);

	free(msg);

	return res;
}

/* Convert an octet string into a non-negative integer */
#ifdef _WIN32_
__declspec(dllexport)
#endif
char *rsa_os2i(unsigned char *message)
{
	int i, msg_size = strlen((char *)message);
	mpz_t x, p, base, zero;
	char *res;

	mpz_init(x);
	mpz_init(p);
	mpz_init(base);
	mpz_init(zero);

	mpz_set_ui(base, 256);

	/* x = message[0] * 256^(n - 1) + message[1] * 256^(n - 2) + ... + message[n] * 256^0
	 * Where n = strlen(message)
	 */
	for (i = 0; i < msg_size; i++)
	{
		mpz_pow_ui(p, base, msg_size - i - 1);
		mpz_addmul_ui(x, p, message[i]);
	}

	if (mpz_cmp(x, zero) < 0)
		printf("WARNING: x is negative!!!\n");

	res = mpz_get_str(NULL, 10, x);

	mpz_clear(x);
	mpz_clear(p);
	mpz_clear(base);
	mpz_clear(zero);

	return res;
}

/* Convert a non-negative integer into a octet string */
#ifdef _WIN32_
__declspec(dllexport)
#endif
char *rsa_i2os(char *number, int msg_size)
{
	int i, j;
	mpz_t number_z, r;
	char *res = (char *)malloc(sizeof(char) * (msg_size + 1));

	mpz_init(number_z);
	mpz_init(r);

	memset(res, 0, sizeof(res));
	mpz_set_str(number_z, number, 10);

	for (i = msg_size - 1; i >= 0; i--)
	{
		mpz_tdiv_qr_ui(number_z, r, number_z, 256);
		res[i] = mpz_get_ui(r);
	}

	/* Remove leading 0s (NULLs) */
	for (i = j = 0; i < msg_size; i++)
	{
		if (res[i] != 0)
			res[j++] = res[i];
		else if (j > 0)
			break;
	}
	res[j] = 0;
	res = (char *)realloc(res, sizeof(char) * (j + 1));

	mpz_clear(number_z);
	mpz_clear(r);

	return res;
}
