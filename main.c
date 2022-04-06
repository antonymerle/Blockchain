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


RSAKeyPair getRSAKeyPair(void);

int main(void)
{
	printf("Hello blockchain !\n");
	RSAKeyPair kpair = getRSAKeyPair();

	free(kpair.pKey);
	free(kpair.sKey);
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
	}

	printf("DEBUG : Print keys to stdout\n");
	printf("%s\n", pri_key);
	printf("%s\n", pub_key);

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