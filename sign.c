#include "sign.h"


int signMsg(uint8_t signBin[SIG_BIN], EVP_PKEY* skey, const uint8_t* msg)
{
	EVP_MD_CTX* ctx;
	size_t siglen = SIG_BIN;			// siglen est ensuite calculée/confirmée par openSSL (SHA256 -> taille fixe)
	size_t msglen = strlen(msg);

	if (!signBin || !skey || !msg)
		return 1;

	ctx = EVP_MD_CTX_new();

	if (!ctx)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return -1;
	}
	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, skey) <= 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return -1;
	}
	if (EVP_DigestSignUpdate(ctx, msg, msglen) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return -1;
	}


	// TODO : est-ce qu'on est pas toujours sur 256 bytes ? 
	// Check EVP_MAX_MD_SIZE  https://www.openssl.org/docs/man1.1.1/man3/EVP_MD_CTX_pkey_ctx.html
	// TODO : dans ce cas là, pas besoin d'allouer de la mémoire dynamiquement
	/* first call to determine buffer length, does not compute signature => fast process */
	if (EVP_DigestSignFinal(ctx, NULL, &siglen) <= 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	// we have the signature lenght, so we can allocate memory
	//signature = malloc(siglen);


	//if (signature == NULL)
	//{
	//	fprintf(stderr, "%s", "Impossible d'allouer la mémoire.\n");
	//	exit(1);
	//}

	memset(signBin, '\0', siglen);

	if (EVP_DigestSignFinal(ctx, signBin, &siglen) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return -1;
	}

	printf("Signature is: ");
	int i;
	for (i = 0; i < siglen; i++)
		printf("%.2X ", signBin[i]);
	printf("\n");

	EVP_MD_CTX_free(ctx);
	return 0;
}

bool verifyStrMsg(EVP_PKEY* pubkey, uint8_t* signature, uint8_t* msg)
{
	EVP_MD_CTX* ctx;
	bool validity;
	int validityStatus;
	size_t mlen = strlen(msg);
	size_t mdLen = 256;

	ctx = EVP_MD_CTX_new();
	validity = false;
	validityStatus = 0;

	printf("\nverifyStrMsg.c Signature is: ");
	int i;
	for (i = 0; i < 256; i++)
		printf("%.2X ", signature[i]);
	printf("\n");

	if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return false;
	}

	if (EVP_DigestVerifyUpdate(ctx, msg, mlen) == 0)		// TODO replace 1024 by msgLen;
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return false;
	}

	validityStatus = EVP_DigestVerifyFinal(ctx, signature, mdLen);			//

	switch (validityStatus)
	{
	case 1:
		validity = true;
		break;
	case 0:
		validity = false;
		break;
	default:
		validity = false;
		printf("Error validating signature\n");
		break;
	}

	EVP_MD_CTX_free(ctx);

	return validity;
}



int signFile(uint8_t signBin[SIG_BIN], EVP_PKEY* skey, const uint8_t* filePath)
{
	FILE* fp;
	uint8_t* buffer;
	EVP_MD_CTX* ctx;
	size_t siglen = SIG_BIN;		// siglen est calculé par openSSL

	fp = fopen(filePath, "rb");

	if (fp == NULL)
	{
		fprintf(stderr, "Impossible d'ouvrir le fichier.\n");
		return 1;
	}

	buffer = malloc(READ_FILE_BUFFER_16K0);

	if (buffer == NULL)
	{
		fprintf(stderr, "Impossible d'allouer la mémoire\n");
		exit(1);
	}

	memset(buffer, 0, READ_FILE_BUFFER_16K0);

	ctx = EVP_MD_CTX_new();

	if (!ctx)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}
	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, skey) <= 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return 1;
	}

	while (feof(fp) == 0)
	{
		size_t bytesRead = fread(buffer, 1, READ_FILE_BUFFER_16K0, fp);		// read one byte 1024 * 16 times and chove it in buffer

		if (EVP_DigestSignUpdate(ctx, buffer, bytesRead) == 0)
		{
			fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
			EVP_MD_CTX_free(ctx);
			return 1;
		}
	}

	free(buffer);
	fclose(fp);


	// TODO : est-ce qu'on est pas toujours sur 256 bytes ? 
	// Check EVP_MAX_MD_SIZE  https://www.openssl.org/docs/man1.1.1/man3/EVP_MD_CTX_pkey_ctx.html
	// TODO : dans ce cas là, pas besoin d'allouer de la mémoire dynamiquement
	/* first call to determine buffer length, does not compute signature => fast process */
	if (EVP_DigestSignFinal(ctx, NULL, &siglen) <= 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return NULL;
	}

	// TODO assert(siglen == SIG_BIN)

	memset(signBin, '\0', siglen);

	if (EVP_DigestSignFinal(ctx, signBin, &siglen) == 0)
	{
		fprintf(stderr, "%s", ERR_error_string(ERR_get_error(), NULL));
		EVP_MD_CTX_free(ctx);
		return NULL;
	}

	//printf("Signature is: ");
	//int i;
	//for (i = 0; i < siglen; i++)
	//	printf("%.2X ", signBin[i]);
	//printf("\n");

	EVP_MD_CTX_free(ctx);
	return 0;
}
