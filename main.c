#include <openssl/evp.h>
#include <openssl/applink.c>
#include "common.h"
#include "account.h"
#include "digest.h"
#include "sign.h"

#define TEST_SIGNATURE_MSG 0
#define TEST_SIGNATURE_FILE 1


int main(void)
{
	printf("Hello blockchain !\n");
#if 0
	while (0)
	{
		EVP_PKEY* key = newEVP_PKEY();

		writeKeysPEM(key, DEBUG_PATH);

		EVP_PKEY_free(key);
	}

	EVP_PKEY* key = newEVP_PKEY();


	const uint8_t* path = concat(DEBUG_PATH, "1646733517396.webm");


	uint8_t hashResult[SHA256_DIGEST_LENGTH] = { 0 };
	uint8_t hexHash[HEX_HASH_NT_LEN] = { 0 };
	//uint8_t signature[SHA256_DIGEST_LENGTH] = { 0 };

	hashFile(hashResult, path);

	hash2Hex(hexHash, hashResult);

	printf("hash fichier : ");
	printf("%s\n", hexHash);


	hashStr(hashResult, "Hello world !");
	hash2Hex(hexHash, hashResult);
	printf("hash string : %s\n", hexHash);

	Personne personne = { .prenom = "Antony", .nom = "Merle", .taille = 177 };

	printf("%s %s %zu cm\n", personne.prenom, personne.nom, personne.taille);


	hashFile(hashResult, path);

	free(path);

	/* =================================================== */

	uint8_t* signature = signMsg2(key, hashResult);

	// TODO : implement verification fonction. fn verifier(message, signature, pk) -> bool

	//memset(hashResult, '\0', SHA256_DIGEST_LENGTH);

	//hashData(&personne, hashResult);
	//uint8_t* hashStruct = hash2Hex(hexHash, hashResult);		// TODO : hashe le pointeur mais pas le contenu. Faire une fonction par type.


	//printf("hash struct : %s\n", hashStruct);

	EVP_PKEY_free(key);

	free(signature);

#endif
	/* =================================================== */

#if 0
	const uint8_t* pathKey = concat(DEBUG_PATH, "private.pem");

	EVP_PKEY* keyfromfile = EVP_PKEY_new();

	loadKeyFromPEMFile(&keyfromfile, pathKey);

	BIO* bio = NULL;
	bio = BIO_new_fp(stdout, BIO_NOCLOSE);

	print_PEM_key(keyfromfile, PKEY);
	puts("\n");
	print_PEM_key(keyfromfile, SKEY);
	puts("\n");


	

	EVP_PKEY_free(keyfromfile);
	BIO_free(bio);
	free(pathKey);
#endif
	// no leak

#if TEST_SIGNATURE_MSG

	while (1)
	{
		//const uint8_t* path = concat(DEBUG_PATH, "1646733517396.webm");


		uint8_t hashResult[SHA256_DIGEST_LENGTH] = { 0 };
		uint8_t hexHash[HEX_HASH_NT_LEN] = { 0 };

		//hashFile(hashResult, path);
		hashStr(hashResult, "Hello world !");

		hash2Hex(hexHash, hashResult);

		printf("hash string : ");
		printf("%s\n", hexHash);

		const uint8_t* pathKey = concat(DEBUG_PATH, "private.pem");

		EVP_PKEY* keyfromfile = EVP_PKEY_new();

		loadKeyFromPEMFile(&keyfromfile, pathKey);

		BIO* bio = NULL;
		bio = BIO_new_fp(stdout, BIO_NOCLOSE);

		print_PEM_key(keyfromfile, PKEY);
		puts("\n");
		print_PEM_key(keyfromfile, SKEY);
		puts("\n");

		size_t slen = 0;
		uint8_t* signature = signMsg(keyfromfile, "Hello world !");

		printf("\nmain.c Signature is: ");
		int i;
		for (i = 0; i < 256; i++)
			printf("%.2X ", signature[i]);
		printf("\n");

		bool legit = false;
		//memset(hashResult, 0, SHA256_DIGEST_LENGTH);

		legit = verifyStrMsg(keyfromfile, signature, "Hello world !");
		
		legit ? printf("La signature est valide\n") : printf("La signature est invalide\n");

		EVP_PKEY_free(keyfromfile);
		BIO_free(bio);

		free(pathKey);
		//free(path);
		free(signature);
		break;

		// no leak
	}
	

#endif

#if TEST_SIGNATURE_FILE

while (1)
{
	uint8_t* filePath = concat(DEBUG_PATH, "1646733517396.webm");

	uint8_t* pathKey = concat(DEBUG_PATH, "private.pem");

	EVP_PKEY* keyfromfile = EVP_PKEY_new();

	loadKeyFromPEMFile(&keyfromfile, pathKey);

	//BIO* bio = NULL;
	//bio = BIO_new_fp(stdout, BIO_NOCLOSE);

	// TODO : fn printKeys

	print_PEM_keys(keyfromfile);

	//size_t slen = 0;
	uint8_t signature[SIG_BIN] = {0};
	signMsg(signature, keyfromfile, "Hello world !");

	uint8_t hexBuffer[SIG_HEX_NT] = {0};
	bin2Hex(hexBuffer, SIG_HEX_NT, signature, SIG_BIN);

	hexPrettyPrint(hexBuffer);

	bool legit = false;

	legit = verifyStrMsg(keyfromfile, signature, "Hello world !");

	legit ? printf("La signature est valide\n") : printf("La signature est invalide\n");

	printf("\nsign file\n");

	memset(signature, 0, SIG_BIN);
	memset(hexBuffer, 0, SIG_HEX_NT);

	signFile(signature, keyfromfile, filePath);
	bin2Hex(hexBuffer, SIG_HEX_NT, signature, SIG_BIN);
	hexPrettyPrint(hexBuffer);

	legit = false;

	uint8_t* filePath2 = concat(DEBUG_PATH, "test.py");

	legit = verifyFileSignature(keyfromfile, signature, filePath2);

	legit ? printf("La signature est valide\n") : printf("La signature est invalide\n");

	EVP_PKEY_free(keyfromfile);
	//BIO_free(bio);

	free(pathKey);
	free(filePath);
	free(filePath2);


	// no leak
}

#endif

	return EXIT_SUCCESS;
}