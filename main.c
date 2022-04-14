#include <openssl/evp.h>
#include <openssl/applink.c>
#include "common.h"
#include "account.h"
#include "digest.h"
#include "sign.h"


int main(void)
{
	printf("Hello blockchain !\n");

	while (0)
	{
		EVP_PKEY* key = newEVP_PKEY();

		writeKeysPEM(key, DEBUG_PATH);

		EVP_PKEY_free(key);
	}

	EVP_PKEY* key = newEVP_PKEY();

	const uint8_t* path = concat(DEBUG_PATH, "1646733517396.webm");


	uint8_t hashResult[SHA256_DIGEST_LENGTH] = { 0 };
	uint8_t hexHash[HEX_SHA256_NULLT_LEN] = { 0 };
	uint8_t signature[SHA256_DIGEST_LENGTH] = { 0 };

	hashFile(hashResult, path);

	hash2Hex(hexHash, hashResult);

	printf("hash fichier : ");
	printf("%s\n", hexHash);


	hashData(hashResult, "Hello world !");
	hash2Hex(hexHash, hashResult);
	printf("hash string : %s\n", hexHash);

	Personne personne = { .prenom = "Antony", .nom = "Merle", .taille = 177};

	printf("%s %s %zu cm\n", personne.prenom, personne.nom, personne.taille);

	signFile(signature, key, path);

		//memset(hashResult, '\0', SHA256_DIGEST_LENGTH);

		//hashData(&personne, hashResult);
		//uint8_t* hashStruct = hash2Hex(hashResult);		// TODO : hashe le pointeur mais pas le contenu. Faire une fonction par type.


		//printf("hash struct : %s\n", hashStruct);

	free(path);
	EVP_PKEY_free(key);

	return EXIT_SUCCESS;
}