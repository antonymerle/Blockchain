#include "account.h"

EVP_PKEY* newEVP_PKEY(void)
{
	RSA* rsa;
	EVP_PKEY* key;
	EVP_PKEY_CTX* ctx;

	rsa = RSA_new();
	key = EVP_PKEY_new();
	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY_keygen_init(ctx);
	EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
	EVP_PKEY_keygen(ctx, &key);

	RSA_free(rsa);
	EVP_PKEY_CTX_free(ctx);

	return key;
}

void writeKeysPEM(EVP_PKEY* key, const uint8_t* path)
{
	FILE* fp;

	const uint8_t* skeyPath = concat(path, "private.pem");
	const uint8_t* pkeyPath = concat(path, "public.pem");

	fp = fopen(skeyPath, "w");
	PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);		// EVP_aes_256_cbc() pour crypter, NULL pour écrire la clé en clair
	fclose(fp);

	fp = fopen(pkeyPath, "w");

	PEM_write_PUBKEY(fp, key);
	fclose(fp);

	free(skeyPath);
	free(pkeyPath);
}

// create a EVP_PKEY structure from private key

int loadKeyFromPEMFile(EVP_PKEY** key, const uint8_t* filePath)
{
	FILE* fp;
	
	if (filePath == NULL)
		return 1;

	fp = fopen(filePath, "r");

	if (fp == NULL)
	{
		fprintf(stderr, "%s : %s\n", "Impossible d'ouvrir le chemin", filePath);
		return 1;
	}

	PEM_read_PrivateKey(fp, key, NULL, NULL);
	PEM_write_PrivateKey(stdout, *key, NULL, NULL, 0, NULL, NULL);

	return 0;
}