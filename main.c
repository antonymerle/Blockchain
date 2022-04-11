#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/applink.c>
#include "defs.h"

typedef struct {
	EVP_PKEY* pKey;
	EVP_PKEY* sKey;
} RSAKeyPair;


RSAKeyPair getRSAKeyPair(void);
int writeKeyToFile(uint8_t* keyString, KeyType keyType);
uint8_t* concat(const uint8_t* strA, const uint8_t* strB);
EVP_PKEY* GenerKey();
void writeToFile(EVP_PKEY* pkey);

void getEVP_PKEY(void);

int main(void)
{
	printf("Hello blockchain !\n");
	//RSAKeyPair kpair = getRSAKeyPair();

	//free(kpair.pKey);
	//free(kpair.sKey);

	getEVP_PKEY();

	return EXIT_SUCCESS;
}

RSAKeyPair getRSAKeyPair(void)
{
	RSAKeyPair keyPair = {0};
	BIGNUM* bigNum = BN_new();
	BN_set_word(bigNum, RSA_F4);

	int bits = 2048;
	RSA* rsa = RSA_new();
	RSA_generate_key_ex(rsa, bits, bigNum, NULL);

	/* We use a BIO to store the keys */
	BIO* bp_public = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPublicKey(bp_public, rsa);

	BIO* bp_private = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);

	size_t pri_len = BIO_pending(bp_private);				/* once the data is written to a memory/file BIO , we get the size */
	size_t pub_len = BIO_pending(bp_public);

	uint8_t* pri_key = (uint8_t*)malloc(pri_len + 1);
	uint8_t* pub_key = (uint8_t*)malloc(pub_len + 1);

	BIO_read(bp_private, pri_key, pri_len);					/* now we read the BIO into a buffer */
	BIO_read(bp_public, pub_key, pub_len);

	if (pri_key && pub_key)
	{
		pri_key[pri_len] = '\0';
		pub_key[pub_len] = '\0';

		printf("DEBUG : Print keys to stdout\n");
		printf("%s\n", pri_key);
		printf("%s\n", pub_key);
		puts("\n");

		writeKeyToFile(pri_key, PRIVATE_KEY);
		
		//size_t begin = strlen("-----BEGIN RSA PRIVATE KEY-----");

		//size_t end = strlen("-----END RSA PRIVATE KEY-----");


		//printf("Size of private key : %zu\n", strlen(pri_key) - (begin + end));
		//printf("Size of public key : %zu\n", strlen(pub_key));
	}

	BIO* priv_key_bio = NULL;
	priv_key_bio = BIO_new_mem_buf((void*)pri_key, pub_len);
	BIO* pub_key_bio = NULL;
	pub_key_bio = BIO_new_mem_buf((void*)pub_key, pub_len);

	RSA* pri_rsa = NULL;
	RSA* pub_rsa = NULL;

	pri_rsa = PEM_read_bio_RSAPrivateKey(priv_key_bio, &pri_rsa, NULL, NULL);		/* now we read the BIO to get the RSA key */
	pub_rsa = PEM_read_bio_RSAPublicKey(pub_key_bio, &pub_rsa, NULL, NULL);

	EVP_PKEY* evp_pri_key = EVP_PKEY_new();											/* we want EVP keys , openssl libraries work best with this type, https://wiki.openssl.org/index.php/EVP */
	EVP_PKEY_assign_RSA(evp_pri_key, pri_rsa);

	EVP_PKEY* evp_pub_key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(evp_pub_key, pub_rsa);

	/* menage */
	free(pri_key);
	free(pub_key);

	BIO_free_all(bp_private);
	BIO_free_all(bp_public);

	BIO_free(priv_key_bio);
	BIO_free(pub_key_bio);

	BN_free(bigNum);
	RSA_free(rsa);

	keyPair.pKey = evp_pub_key;
	keyPair.sKey = evp_pri_key;

	return keyPair;
}

int writeKeyToFile(uint8_t* keyString, KeyType keyType)
{
	FILE* fp;

	uint8_t* path = "C:\\Users\\lain\\Desktop\\test_blockchain_c\\";
	uint8_t* filename = keyType == PUBLIC_KEY ? "public.pem" : "private.pem";

	/*const size_t pathBufferLength = strlen(path) + strlen(filename) + 1;
	uint8_t* keyPath = malloc(pathBufferLength);*/

	uint8_t* keyPath = concat(path, filename);

	if (keyPath == NULL) return -1;
	
	fp = fopen(keyPath, "w");

	if (fp)
		fputs(keyString, fp);
	else
	{
		printf("Failed to open file : %s\n", keyPath);
		return -1;
	}
	
	fclose(fp);
	free(keyPath);

	return 0;
}

uint8_t* concat(const uint8_t* strA, const uint8_t* strB)
{
	uint8_t* result;

	result = malloc(strlen(strA) + strlen(strB) + 1);	// +1 for the null terminator;
	if (result == NULL) exit(-1);

	strcpy(result, strA);
	strcat(result, strB);

	return result;
}


EVP_PKEY* GenerKey()
{

	//1. Create an RSA public key encryption context, parameter 1 is the algorithm type
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!ctx)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}
	//2, initialization key pair generation context
	int ret = EVP_PKEY_keygen_init(ctx);
	if (!ret)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}
	//Set parameters, RSA's key bits 1024 bits
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024) <= 0)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}
	//4, key generation
	EVP_PKEY* pkey = NULL;
	//Interior has a malloc application
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
	{
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		return NULL;
	}
	EVP_PKEY_CTX_free(ctx);
	FILE* fp1 = fopen("./public.pem", "w");
	if (!fp1)
	{
		//Error handling
	}
	PEM_write_RSAPublicKey(fp1, EVP_PKEY_get0_RSA(pkey));
	FILE* fp2 = fopen("./private.pem", "w");
	if (!fp2)
	{
		//Error handling
	}
	//Store in a clear text
	PEM_write_RSAPrivateKey(fp2, EVP_PKEY_get0_RSA(pkey),
		NULL,//Encrypted context
		NULL,//key
		0,//Key length
		NULL,//Callback
		NULL //Tune parameters
	);
	fclose(fp1);
	fclose(fp2);
	return pkey;
}

void writeToFile(EVP_PKEY* pkey)
{
	FILE* fp2 = fopen("./private.pem", "w");
	//Store in a clear text
	PEM_write_RSAPrivateKey(fp2, EVP_PKEY_get0_RSA(pkey),
		NULL,//Encrypted context
		NULL,//key
		0,//Key length
		NULL,//Callback
		NULL //Tune parameters
	);
	fclose(fp2);
}

void getEVP_PKEY(void)
{
	FILE* fp;

	RSA* rsa = RSA_new();

	EVP_PKEY* key = EVP_PKEY_new();
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY_keygen_init(ctx);
	EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096);
	EVP_PKEY_keygen(ctx, &key);

	fp = fopen("private.pem", "w");
	PEM_write_PrivateKey(fp, key, EVP_aes_256_cbc(), NULL, 0, NULL, NULL);		// EVP_aes_256_cbc() pour crypter, NULL pour écrire la clé en clair
	fclose(fp);

	fp = fopen("public.pem", "w");

	PEM_write_PUBKEY(fp, key);
	fclose(fp);

	EVP_PKEY_CTX_free(ctx);
}