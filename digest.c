#include "common.h"
#include "digest.h"

/* 
* Writes SHA256 hash of the file into the empty message digest passed as argument.
* The hash produced is a binary representation (32*8 bytes)
*/
int digest_hash_file(uint8_t binmd[SHA256_DIGEST_LENGTH], uint8_t* const filePath)			// 256 bits, 32 bytes
{
	FILE* fp;
	SHA256_CTX ctx;
	uint8_t* buffer;

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

	buffer = malloc(READ_FILE_BUFFER_16K0_SZ);

	if (buffer == NULL)
	{
		fprintf(stderr, "%s", "Impossible d'allouer la mémoire.\n");
		exit(1);
	}

	memset(buffer, 0, READ_FILE_BUFFER_16K0_SZ);

	while (feof(fp) == 0)
	{
		size_t totalRead = fread(buffer, 1, READ_FILE_BUFFER_16K0_SZ, fp);

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
int digest_hash_str(uint8_t binmd[SHA256_DIGEST_LENGTH], uint8_t* const str)			// 256 bits, 32 bytes
{
	SHA256_CTX ctx;

	// TODO : do some hardening.

	memset(binmd, '\0', SHA256_DIGEST_LENGTH);

	if (SHA256_Init(&ctx) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	if (SHA256_Update(&ctx, str, strlen(str)) == 0)
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

int digest_pair_bin_leaves(LeavesPair* lp, uint8_t left[SHA256_DIGEST_LENGTH], uint8_t right[SHA256_DIGEST_LENGTH])
{
	memcpy(lp->left, left, SHA256_DIGEST_LENGTH);

	memcpy(lp->right, right, SHA256_DIGEST_LENGTH);
	return 0;
}

int digest_hash_bin_pair_leaves(uint8_t bin_hash_result[SHA256_DIGEST_LENGTH], LeavesPair* const lp)
{
	SHA256_CTX ctx;

	// TODO : do some hardening.

	memset(bin_hash_result, '\0', SHA256_DIGEST_LENGTH);

	if (SHA256_Init(&ctx) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	if (SHA256_Update(&ctx, lp->left, SHA256_DIGEST_LENGTH) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	if (SHA256_Update(&ctx, lp->right, SHA256_DIGEST_LENGTH) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	if (SHA256_Final(bin_hash_result, &ctx) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	return 0;
}

int digest_merkle_root(uint8_t merkle_root[SHA256_DIGEST_LENGTH], size_t leaves_number, uint8_t leaves_bin[])
{

	//LeavesPair leaves_pair[SHA256_DIGEST_LENGTH] = { 0 };
	//uint8_t halved_leaves[SHA256_DIGEST_LENGTH] = { 0 };

	//bool leaves_number_is_odd = leaves_number % 2 == 0 ? false : true;

	//size_t i;

	//for (i = 0; i < leaves_number; i += 2)
	//{
	//	digest_concatenate_leaves_pair(leaves_pair, leaves_bin[i], leaves_bin[i + 1]);

	//}
}

int digest_hash_merkle_proof(uint8_t binmd[SHA256_DIGEST_LENGTH], uint8_t* const tx_hash_buffer_bin, size_t buffer_size)
{
	size_t i;
	size_t hash_count;
	SHA256_CTX ctx;

	memset(binmd, '\0', SHA256_DIGEST_LENGTH);

	if (SHA256_Init(&ctx) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}
	
	hash_count = buffer_size / SHA256_DIGEST_LENGTH;

	for (i = 0; i < hash_count; i++)
	{
		if (SHA256_Update(&ctx, &(tx_hash_buffer_bin[i * SHA256_DIGEST_LENGTH]), SHA256_DIGEST_LENGTH) == 0)
		{
			fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
			return -1;
		}
	}
	

	if (SHA256_Final(binmd, &ctx) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	return 0;
}


/*
* Writes in hexmd buffer an hexadecimal representation of a SHA256 binary hash/signature, in order to display it as a string.
* The caller must allocate an array of IO_BUFFER_SZ lenght on the stack to serve as a destination buffer (hexmd).
* Since it is an hexadecimal representation, 4 bits are enough to encode each character (instead of 8, like for ASCII),
* so 256 bits can be layed on 64 hex characters.
*/
int digest_bin_2_hex(uint8_t hexmd[HEX_HASH_NT_SZ], IO_BUFFER_SZ OUT_SZ, uint8_t const binmd[SHA256_DIGEST_LENGTH], IO_BUFFER_SZ IN_SZ)
{
	size_t i;

	if (!hexmd || !binmd || !OUT_SZ || !IN_SZ)
		return 1;

	memset(hexmd, '\0', OUT_SZ);

	for (i = 0; i < IN_SZ; i++)
		sprintf(&hexmd[i * 2], "%.2X", binmd[i]);

	return 0;
}

/*
* Writes a SHA256 binary hash/signature in binmd based on the hexmd hexadecimal representation.
* The caller must allocate an array of SHA256_DIGEST_LENGTH on the stack to serve as a destination buffer (bin).
* Since it is an hexadecimal representation, 4 bits are enough to encode each character (instead of 8, like for ASCII),
* so 256 bits can be layed on 64 hex characters.
*/
int digest_hex_2_bin(uint8_t binmd[], IO_BUFFER_SZ OUT_SZ, uint8_t const hexmd[], IO_BUFFER_SZ IN_SZ)
{
	size_t len = 0;
	if (!(&binmd[0]) || !hexmd || !OUT_SZ || !IN_SZ)
		return 1;

	uint8_t* temp_buffer = OPENSSL_hexstr2buf(hexmd, (long*)&len);

	if (len != OUT_SZ)
	{
		fprintf(stderr, "Error, digest_hex_2_bin : destination buffer size. Expected %zu, got %zu\n", len, (size_t)IN_SZ);
		return 1;
	}

	memset(binmd, 0, len);
	memcpy(binmd, temp_buffer, OUT_SZ);
	
	free(temp_buffer);
	return 0;
}


/* Displays 16 * 16 hex digits block */
void digest_hex_pretty_print(uint8_t const hexsig[])
{
	size_t i;
	uint8_t* p;

	if (!hexsig)
		return;

	i = 0;
	p = (uint8_t* const) hexsig;				// silence C4090 warning

	while (*p)
	{
		putchar(*p++);
		putchar(*p++);
		i++;
		i % 16 ? putchar(' ') : putchar('\n');
	}
}

int digest_wb32_file(uint8_t* const path, size_t sz, uint8_t* bin_buffer)
{
	FILE* fp;

	if (path == NULL)
		return 1;

	fp = fopen(path, "wb");

	if (fp == NULL)
	{
		fprintf(stderr, "%s : %s\n", "Impossible d'ouvrir le chemin", path);
		return 1;
	}

	fwrite(bin_buffer, sz, 1, fp);

	fclose(fp);

	return 0;
}

int digest_wb64_file(uint8_t* const path, size_t sz, LeavesPair* lp)
{
	FILE* fp;

	if (path == NULL)
		return 1;

	fp = fopen(path, "wb");

	if (fp == NULL)
	{
		fprintf(stderr, "%s : %s\n", "Impossible d'ouvrir le chemin", path);
		return 1;
	}

	fwrite(lp->left, sz, 1, fp);
	fwrite(lp->right, sz, 1, fp);

	fclose(fp);

	return 0;
}