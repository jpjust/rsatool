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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
	struct rsa_key_st mykey;	/* The struct which holds the key */
	FILE *fd;
	char opt[3], input[1000], *result;
	int keysize;

	begin:
	do
	{
		printf("\n\nRSA Tool UI menu\n----------------\n\n");
		printf("1: Generate a RSA key\n");
		printf("2: Encrypt a message\n");
		printf("3: Decrypt a message\n");
		printf("\n0: Quit\n");
		printf("\nChoose an option [0-3]: ");
		fgets(opt, 3, stdin);
	} while ((opt[0] > '3') || (opt[0] < '0'));

	switch (opt[0])
	{
	case '0':
		return 0;

	case '1':	/* Generates the RSA key */
		printf("\nRSA key generation\n------------------\n\n");
		printf("Type the size of the key in bits: ");
		memset(input, 0, 1000);
		fgets(input, 100, stdin);
		keysize = atoi(input);
		printf("Generating RSA key... ");

		mykey = rsa_genkey(keysize);

		printf("Key successfully generated! Enter a filename to save the key: ");
		memset(input, 0, 1000);
		fgets(input, 256, stdin);
		*(strchr(input, '\n')) = 0;

		if ((fd = fopen(input, "w")) == NULL)
		{
			printf("ERROR: Could not open the file for writting!\n");
			break;
		}

		fprintf(fd, "%d\n", mykey.size);
		fputs(mykey.n, fd);
		fputs("\n", fd);
		fputs(mykey.e, fd);
		fputs("\n", fd);
		fputs(mykey.d, fd);
		fputs("\n", fd);
		fclose(fd);

		printf("File has been saved. Press ENTER to continue.\n");
		getchar();
		break;

	case '2':	/* Encrypts a text */
		printf("\nText encryption\n---------------\n\n");
		printf("Enter the filename of the saved key to use: ");
		memset(input, 0, 1000);
		fgets(input, 256, stdin);
		*(strchr(input, '\n')) = 0;

		if ((fd = fopen(input, "r")) == NULL)
		{
			printf("ERROR: Could not open the file for reading!\n");
			break;
		}

		mykey.n = (char *)malloc(sizeof(char) * 1000);
		mykey.e = (char *)malloc(sizeof(char) * 1000);
		mykey.d = (char *)malloc(sizeof(char) * 1000);
		memset(input, 0, 1000);
		fgets(input, 1000, fd);
		mykey.size = atoi(input);
		fgets(mykey.n, 1000, fd);
		fgets(mykey.e, 1000, fd);
		fgets(mykey.d, 1000, fd);

		*(strchr(mykey.n, '\n')) = 0;
		*(strchr(mykey.e, '\n')) = 0;
		*(strchr(mykey.d, '\n')) = 0;

		fclose(fd);

		printf("Type the text to encrypt (max. of %d chars):\n", mykey.size / 8);
		memset(input, 0, 1000);
		fgets(input, 1000, stdin);
		*(strchr(input, '\n')) = 0;

		result = rsa_encrypt(input, mykey);
		printf("The encrypted text is:\n%s\n", result);
		printf("\nType a filename to save this text: ");
		memset(input, 0, 1000);
		fgets(input, 256, stdin);
		*(strchr(input, '\n')) = 0;

		if ((fd = fopen(input, "w")) == NULL)
		{
			printf("ERROR: Could not open the file for writting!\n");
			break;
		}

		fputs(result, fd);
		fclose(fd);

		printf("The encrypted text has been saved successfully. Press ENTER to continue.\n");
		getchar();

		free(mykey.n);
		free(mykey.e);
		free(mykey.d);
		free(result);

		break;

	case '3':	/* Decrypt a text */
		printf("\nText decryption\n---------------\n\n");
		printf("Enter the filename of the saved key: ");
		memset(input, 0, 1000);
		fgets(input, 256, stdin);
		*(strchr(input, '\n')) = 0;

		if ((fd = fopen(input, "r")) == NULL)
		{
			printf("ERROR: Could not open the file for reading!\n");
			break;
		}

		mykey.n = (char *)malloc(sizeof(char) * 1000);
		mykey.e = (char *)malloc(sizeof(char) * 1000);
		mykey.d = (char *)malloc(sizeof(char) * 1000);

		memset(input, 0, 1000);
		fgets(input, 1000, fd);
		mykey.size = atoi(input);
		fgets(mykey.n, 1000, fd);
		fgets(mykey.e, 1000, fd);
		fgets(mykey.d, 1000, fd);

		*(strchr(mykey.n, '\n')) = 0;
		*(strchr(mykey.e, '\n')) = 0;
		*(strchr(mykey.d, '\n')) = 0;

		fclose(fd);

		printf("Enter the filename of the saved encrypted text: ");
		memset(input, 0, 1000);
		fgets(input, 256, stdin);
		*(strchr(input, '\n')) = 0;

		if ((fd = fopen(input, "r")) == NULL)
		{
			printf("ERROR: Could not open the file for reading!\n");
			break;
		}

		memset(input, 0, 1000);
		fgets(input, 1000, fd);
		fclose(fd);

		result = rsa_decrypt(input, mykey);
		printf("The decrypted text is:\n%s\nPress ENTER to continue.", result);
		getchar();

		free(mykey.n);
		free(mykey.e);
		free(mykey.d);
		free(result);

		break;
	}
	goto begin;
}
