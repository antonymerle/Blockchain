#include "account.h"

// TODO : change name to more explicit : createAccount or something
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

// TODO: ajouter un argument pour crypter la clé privée
int writeKeysPEM(EVP_PKEY* const key, uint8_t* const path)
{
	FILE* fp;

	uint8_t* skeyPath;
	uint8_t* pkeyPath; 

	if (!key || !path)
		return 1;

	skeyPath = concat(path, "private.pem");
	pkeyPath = concat(path, "public.pem");

	if (!skeyPath || !pkeyPath)
		return 1;

	fp = fopen(skeyPath, "w");

	if (!fp)
	{
		fprintf(stderr, "Cannot open %s\n", skeyPath);
		return 1;
	}

	PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);		// EVP_aes_256_cbc() pour crypter, NULL pour écrire la clé en clair
	fclose(fp);

	fp = fopen(pkeyPath, "w");

	if (!fp)
	{
		fprintf(stderr, "Cannot open %s\n", pkeyPath);
		return 1;
	}

	PEM_write_PUBKEY(fp, key);
	fclose(fp);

	free(skeyPath);
	free(pkeyPath);

	return 0;
}

/*
* Fills an empty EVP_PKEY structure with skey and pkey
* EVP_PKEY* emptyEVP = EVP_PKEY_new();
*/

int loadKeyFromPEMFile(EVP_PKEY** const key, uint8_t* const filePath)
{
	FILE* fp;
	
	if (!key || !filePath)
		return 1;

	fp = fopen(filePath, "r");

	if (fp == NULL)
	{
		fprintf(stderr, "%s : %s\n", "Impossible d'ouvrir le chemin", filePath);
		return 1;
	}

	PEM_read_PrivateKey(fp, key, NULL, NULL);

	fclose(fp);
	
	return 0;
}

/* Prints public or private key to stdout. */
void print_PEM_key(EVP_PKEY* const key, KEY_TYPE KT)
{
	switch (KT)
	{
	case PKEY:
		PEM_write_PUBKEY(stdout, key);
		break;
	case SKEY:
		PEM_write_PrivateKey(stdout, key, NULL, NULL, 0, NULL, NULL);
		break;
	default:
		break;
	}
}

void print_PEM_keys(EVP_PKEY* const key)
{
	PEM_write_PUBKEY(stdout, key);
	puts("\n");
	PEM_write_PrivateKey(stdout, key, NULL, NULL, 0, NULL, NULL);
	puts("\n");
}