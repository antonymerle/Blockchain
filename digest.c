#include "common.h"
#include "digest.h"

/* 
* Writes SHA256 hash of the file into the empty message digest passed as argument.
* The hash produced is a binary representation (32*8 bytes)
*/
int hashFile(uint8_t* filePath, uint8_t binmd[SHA256_DIGEST_LENGTH])			// 256 bits, 32 bytes
{
	FILE* fp;
	SHA256_CTX ctx;
	uint8_t* buffer;
	size_t i;

	if (filePath == NULL)
		return 1;

	fp = fopen(filePath, "rb");

	if (fp == NULL)
	{
		fprintf(stderr, "%s : %s\n", "Impossible d'ouvrir le chemin", filePath);
		return 1;
	}
		

	if (SHA256_Init(&ctx) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	buffer = malloc(READ_FILE_BUFFER_16K0);

	if (buffer == NULL)
	{
		fprintf(stderr, "%s", "Impossible d'allouer la mémoire.\n");
		exit(1);
	}

	memset(buffer, 0, READ_FILE_BUFFER_16K0);

	while (feof(fp) == 0)
	{
		size_t totalRead = fread(buffer, 1, READ_FILE_BUFFER_16K0, fp);

		if (SHA256_Update(&ctx, buffer, totalRead) == 0)
		{
			fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
			free(buffer);
			return -1;
		}
	}

	free(buffer);
	fclose(fp);

	if (SHA256_Final(binmd, &ctx) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	return 0;
}


/*
* Writes SHA256 hash of the file into the empty message digest passed as argument.
* The hash produced is a binary representation (32*8 bytes)
*/
int hashData(uint8_t* data, uint8_t binmd[SHA256_DIGEST_LENGTH])			// 256 bits, 32 bytes
{
	SHA256_CTX ctx;
	size_t i;

	if (SHA256_Init(&ctx) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}


	if (SHA256_Update(&ctx, data, strlen(data)) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	if (SHA256_Final(binmd, &ctx) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	return 0;
}



/*
* Returns an heap-allocated hexadecimal representation of an SHA256 hash that can be displayed as a normal string.
* Since it's an hexadecimal representation, 4 bits are enough to encode each character (instead of 8, like for ASCII),
* so 256 bits can be layed on 64 hex characters.
*/
uint8_t* hash2Hex(uint8_t binmd[SHA256_DIGEST_LENGTH])
{
	uint8_t* buf;
	size_t i;

	buf = malloc(HEX_SHA256_LEN + 1);
	if (buf == NULL)
	{
		fprintf(stderr, "%s", "Impossible d'allouer la mémoire.\n");
		exit(1);
	}

	memset(buf, '\0', HEX_SHA256_LEN + 1);

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(&buf[i * 2], "%02x", binmd[i]);

	return buf;
}