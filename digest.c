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

int digest_hash_bin(uint8_t ouput_bin_buffer[SHA256_DIGEST_LENGTH], uint8_t const input_bin_buf[SHA256_DIGEST_LENGTH])
{
	SHA256_CTX ctx;

	// TODO : do some hardening.

	memset(ouput_bin_buffer, '\0', SHA256_DIGEST_LENGTH);

	if (SHA256_Init(&ctx) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}

	if (SHA256_Update(&ctx, input_bin_buf, SHA256_DIGEST_LENGTH) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	if (SHA256_Final(ouput_bin_buffer, &ctx) == 0)
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

/* Recieves little endian binary leaves and returns a big endian merkle root */
int digest_merkle_root(uint8_t merkle_root[SHA256_DIGEST_LENGTH], size_t leaves_number, uint8_t leaves_bin[])
{

	size_t i, j, k, l;
	uint8_t* p_child;					
	LeavesPair lp = { 0 };												// une paire de feuilles, temporaire
	uint8_t cat_leaves_first_hash[SHA256_DIGEST_LENGTH] = {0};								// hash en deux passes : sert à stocker la 1ère
	uint8_t cat_leaves_second_hash[SHA256_DIGEST_LENGTH] = { 0 };								// hash en deux passes : sert à stocker la 2nde
	uint8_t children[TPS_MAX * SHA256_DIGEST_LENGTH] = { 0 };			// array pour stocker les hashs finaux des enfants de leaves_bin
	uint8_t cat_orphan_leave_first_hash[SHA256_DIGEST_LENGTH];
	uint8_t cat_orphan_leave_second_hash[SHA256_DIGEST_LENGTH];

	bool leaves_number_is_odd = leaves_number % 2 == 0 ? false : true;

	if (leaves_number_is_odd)
		leaves_number++;

	assert((leaves_number % 2) == 0);



	// on alloue la mémoire pour le niveau supérieur de l'arbre
	//children = calloc(leaves_number / 2, SHA256_DIGEST_LENGTH);

	if (!children)
		return 1;

	// take care of orphan node, concatenate it with itself at the end of children[].
	if (leaves_number_is_odd)
	{
		memset(cat_orphan_leave_first_hash, 0, SHA256_DIGEST_LENGTH);					// prépare le buffer temporaire pour la feuille orpheline
		memset(cat_orphan_leave_second_hash, 0, SHA256_DIGEST_LENGTH);					// prépare le buffer temporaire pour la feuille orpheline
		memset(&lp, 0, sizeof(LeavesPair));

		digest_pair_bin_leaves(&lp, &leaves_bin[(leaves_number * SHA256_DIGEST_LENGTH) - (SHA256_DIGEST_LENGTH * 2)], &leaves_bin[(leaves_number * SHA256_DIGEST_LENGTH) - (SHA256_DIGEST_LENGTH * 2)]);
		digest_hash_bin_pair_leaves(cat_orphan_leave_first_hash, &lp);
		digest_hash_bin(cat_orphan_leave_second_hash, cat_orphan_leave_first_hash);

		memcpy(&children[(leaves_number * SHA256_DIGEST_LENGTH) - SHA256_DIGEST_LENGTH], cat_orphan_leave_second_hash, SHA256_DIGEST_LENGTH);


		/*p_child = &children[(leaves_number * SHA256_DIGEST_LENGTH) - (SHA256_DIGEST_LENGTH * 2)];
		memcpy(p_child, &leaves_bin[(leaves_number * SHA256_DIGEST_LENGTH) - (SHA256_DIGEST_LENGTH * 2)], SHA256_DIGEST_LENGTH);
		p_child = &children[(leaves_number * SHA256_DIGEST_LENGTH) - SHA256_DIGEST_LENGTH];
		memcpy(p_child, &leaves_bin[(leaves_number * SHA256_DIGEST_LENGTH) - (SHA256_DIGEST_LENGTH * 2)], SHA256_DIGEST_LENGTH);*/
	}

	// ok

	p_child = children;

	if (leaves_number_is_odd)
	{
		for (i = j = 0; j < leaves_number - 2; i++, j+=2)				// -2 : last leaf has already been concatenated at the end of children[]
		{
			memset(&lp, 0, sizeof(LeavesPair));
			memset(cat_orphan_leave_first_hash, 0, SHA256_DIGEST_LENGTH);					// prépare le buffer temporaire pour la feuille orpheline
			memset(cat_orphan_leave_second_hash, 0, SHA256_DIGEST_LENGTH);					// prépare le buffer temporaire pour la feuille orpheline

			digest_pair_bin_leaves(&lp, &leaves_bin[j * SHA256_DIGEST_LENGTH], &leaves_bin[j * SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH]);

			digest_hash_bin_pair_leaves(cat_orphan_leave_first_hash, &lp);
			digest_hash_bin(cat_orphan_leave_second_hash, cat_orphan_leave_first_hash);
			memcpy(&p_child[i * SHA256_DIGEST_LENGTH], cat_orphan_leave_second_hash, SHA256_DIGEST_LENGTH);
		}
	}
	else
	{
		for (i = j = 0; j < leaves_number; i++, j += 2)
		{
			memset(&lp, 0, sizeof(LeavesPair));
			memset(cat_orphan_leave_first_hash, 0, SHA256_DIGEST_LENGTH);					// prépare le buffer temporaire pour la feuille orpheline
			memset(cat_orphan_leave_second_hash, 0, SHA256_DIGEST_LENGTH);					// prépare le buffer temporaire pour la feuille orpheline

			digest_pair_bin_leaves(&lp, &leaves_bin[j * SHA256_DIGEST_LENGTH], &leaves_bin[j * SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH]);

			digest_hash_bin_pair_leaves(cat_orphan_leave_first_hash, &lp);
			digest_hash_bin(cat_orphan_leave_second_hash, cat_orphan_leave_first_hash);
			memcpy(&p_child[i * SHA256_DIGEST_LENGTH], cat_orphan_leave_second_hash, SHA256_DIGEST_LENGTH);

			//digest_pair_bin_leaves(&lp, &leaves_bin[j * SHA256_DIGEST_LENGTH], &leaves_bin[j * SHA256_DIGEST_LENGTH + SHA256_DIGEST_LENGTH]);
			//digest_hash_bin_pair_leaves(&p_child[i * SHA256_DIGEST_LENGTH], &lp);
		}
	}

	// exit condition
	if (leaves_number == 2)
	{

		// Here we swap back bytes order from LE to BE

		k = 0;
		l = (size_t)SHA256_DIGEST_LENGTH - 1;

		while (k < SHA256_DIGEST_LENGTH)
		{
			merkle_root[k++] = children[l--];
		}


		//memcpy(merkle_root, children, SHA256_DIGEST_LENGTH);
		return 0;
	}

	digest_merkle_root(merkle_root, leaves_number / 2, children);
	
	return 0;
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
int digest_hex_2_bin(uint8_t binmd[SHA256_DIGEST_LENGTH], uint8_t const hexmd[HEX_HASH_NT_SZ])
{
	size_t len = 0;
	if (!(&binmd[0]) || !hexmd)
		return 1;

	uint8_t* temp_buffer = OPENSSL_hexstr2buf(hexmd, (long*)&len);

	memset(binmd, 0, len);
	memcpy(binmd, temp_buffer, SHA256_DIGEST_LENGTH);

	free(temp_buffer);
	return 0;
}



/*
* Writes a SHA256 binary hash/signature in binmd based on the hexmd hexadecimal representation.
* The caller must allocate an array of SHA256_DIGEST_LENGTH on the stack to serve as a destination buffer (bin).
* Since it is an hexadecimal representation, 4 bits are enough to encode each character (instead of 8, like for ASCII),
* so 256 bits can be layed on 64 hex characters.
*/
uint8_t* digest_hex_2_bin_bulk(uint8_t* bin_array, uint8_t* const const hexmd[HEX_HASH_NT_SZ], size_t count)
{
	size_t i;
	size_t len = 0;
	//uint8_t* temp_buffer = NULL;
	uint8_t* p_bin_array;

	if ( !hexmd || count <= 0)
		return NULL;

	bin_array = calloc(count, SHA256_DIGEST_LENGTH);

	if (!bin_array)
	{
		fprintf(stderr, "digest_hex_2_bin() : Cannot allocate memory.\n");
		exit(1);
	}

	p_bin_array = &bin_array[0];

	for (i = 0; i < count; i++)
	{
		uint8_t* temp_buffer = OPENSSL_hexstr2buf(hexmd[i], (long*)&len);

		memcpy(&p_bin_array[i * SHA256_DIGEST_LENGTH], temp_buffer, SHA256_DIGEST_LENGTH);

		free(temp_buffer);
		temp_buffer = NULL;
	}

	//if (len != OUT_SZ)
	//{
	//	fprintf(stderr, "Error, digest_hex_2_bin : destination buffer size. Expected %zu, got %zu\n", len, (size_t)IN_SZ);
	//	return 1;
	//}
	
	return bin_array;
}


/*
* les txids sont représentées en HEX big endian
* quand on les binarise, cet ordre est conservé (big endian)
* or, les txids_bin doivent être traitées en little endian
*/
uint8_t* digest_hex_2_bin_bulk_to_lendian(uint8_t* bin_array, uint8_t* const const hexmd[HEX_HASH_NT_SZ], size_t count)
{
	size_t i, j, k;
	size_t len = 0;
	uint8_t* p_bin_array;

	if (!hexmd || count <= 0)
		return NULL;

	bin_array = calloc(count, SHA256_DIGEST_LENGTH);

	if (!bin_array)
	{
		fprintf(stderr, "digest_hex_2_bin() : Cannot allocate memory.\n");
		exit(1);
	}

	p_bin_array = &bin_array[0];

	for (i = 0; i < count; i++)
	{
		uint8_t* temp_buffer = OPENSSL_hexstr2buf(hexmd[i], (long*)&len);
		uint8_t temp_buffer_lendian[SHA256_DIGEST_LENGTH] = {0};		// TODO : reverse bytes
		uint8_t* p_temp_buffer_lendian = temp_buffer_lendian;

		// Here we swap bytes order from BE to LE

		j = 0;
		k = (size_t)SHA256_DIGEST_LENGTH - 1;

		while (j < SHA256_DIGEST_LENGTH)
		{
			temp_buffer_lendian[j++] = temp_buffer[k--];
		}

		// TODO : extra copy, why not dump LE bytes directly to bin_array ?
		memcpy(&p_bin_array[i * SHA256_DIGEST_LENGTH], temp_buffer_lendian, SHA256_DIGEST_LENGTH);

		free(temp_buffer);
		temp_buffer = NULL;
	}

	return bin_array;
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