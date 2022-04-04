#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

typedef struct {
	EVP_PKEY* pKey;
	EVP_PKEY* sKey;
} RSAKeyPair;


void getRSAKeyPair(void);

int main(void)
{
	printf("Hello blockchain !\n");
	getRSAKeyPair();
	return EXIT_SUCCESS;
}

void getRSAKeyPair(void)
{
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
	}

	printf("DEBUG : Print keys to stdout\n");
	printf("%s\n", pri_key);
	printf("%s\n", pub_key);

	free(pri_key);
	free(pub_key);
}