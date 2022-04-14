#include "sign.h"

int signFile(uint8_t signature[SHA256_DIGEST_LENGTH],	EVP_PKEY* skey, const uint8_t* filePath)
{
	FILE* fp;
	EVP_MD_CTX* ctx;
	uint8_t* buffer;
	size_t sigLen = 0;
	size_t i;

	if (filePath == NULL)
		return 1;

	fp = fopen(filePath, "rb");

	if (fp == NULL)
	{
		fprintf(stderr, "%s : %s\n", "Impossible d'ouvrir le chemin", filePath);
		return 1;
	}

	ctx = EVP_MD_CTX_new();

	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, skey) == 0)
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

		if (EVP_DigestSignUpdate(ctx, buffer, totalRead) == 0)
		{
			fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
			free(buffer);
			return -1;
		}
	}

	free(buffer);
	fclose(fp);

	memset(signature, '\0', SHA256_DIGEST_LENGTH);

	if (EVP_DigestFinal(ctx, signature, &sigLen) == 0)			// write md signature in buffer
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}

	printf("Digest is: ");
	for (i = 0; i < sigLen; i++)
		printf("%02x", signature[i]);
	printf("\n");

	EVP_MD_CTX_free(ctx);

	return 0;
}