#include "sign.h"


int signFile2(uint8_t signature[SHA256_DIGEST_LENGTH],	EVP_PKEY* skey, const uint8_t* filePath)
{
	FILE* fp;
	EVP_MD_CTX* ctx;
	//EVP_PKEY_CTX* ctx;
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

	ctx = EVP_MD_CTX_create();
	//ctx = EVP_PKEY_CTX_new(skey, NULL /* no engine */);

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


uint8_t* signMsg(EVP_PKEY* skey, const uint8_t* msg)
{
	uint8_t* signature;

	EVP_PKEY_CTX* ctx;
	/* md is a SHA-256 digest in this example. */

	size_t mdlen = 32, siglen;

	/*
	 * NB: assumes signing_key and md are set up before the next
	 * step. signing_key must be an RSA private key and md must
	 * point to the SHA-256 digest to be signed.
	 */
	ctx = EVP_PKEY_CTX_new(skey, NULL /* no engine */);
	if (!ctx)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}
	if (EVP_PKEY_sign_init(ctx) <= 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_PKEY_CTX_free(ctx);
		return NULL;
		}
	if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_PKEY_CTX_free(ctx);
		return NULL;
			}
	if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	// TODO : est-ce qu'on est pas toujours sur 256 bytes ?
	// TODO : dans ce cas là, pas besoin d'allouer de la mémoire dynamiquement
	/* Determine buffer length */
	if (EVP_PKEY_sign(ctx, NULL, &siglen, msg, mdlen) <= 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	signature = malloc(siglen);


	if (signature == NULL)
	{
		fprintf(stderr, "%s", "Impossible d'allouer la mémoire.\n");
		exit(1);
	}

	memset(signature, '\0', siglen);

	if (EVP_PKEY_sign(ctx, signature, &siglen, msg, mdlen) <= 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}

	printf("Signature is: ");
	int i;
	for (i = 0; i < siglen; i++)
		printf("%02x", signature[i]);
	printf("\n");

	EVP_PKEY_CTX_free(ctx);
	return signature;
}