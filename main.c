#include <openssl/evp.h>
#include <openssl/applink.c>
#include "common.h"
#include "account.h"
#include "digest.h"


int main(void)
{
	printf("Hello blockchain !\n");

	while (0)
	{
		EVP_PKEY* key = newEVP_PKEY();

		writeKeysPEM(key, DEBUG_PATH);

		EVP_PKEY_free(key);
	}

	const uint8_t* path = concat(DEBUG_PATH, "1646733517396.webm");


	uint8_t hashResult[SHA256_DIGEST_LENGTH] = { 0 };

	hashFile(hashResult, path);

	uint8_t* hashFichier = hash2Hex(hashResult);

	printf("hash fichier : ");
	printf("%s\n", hashFichier);

	memset(hashResult, '\0', SHA256_DIGEST_LENGTH);
	hashData(hashResult, "Hello world !");
	uint8_t* hashStr = hash2Hex(hashResult);
	printf("hash string : %s\n", hashStr);

	Personne personne = { .prenom = "Antony", .nom = "Merle", .taille = 177};

	printf("%s %s %zu cm\n", personne.prenom, personne.nom, personne.taille);

	//memset(hashResult, '\0', SHA256_DIGEST_LENGTH);

	//hashData(&personne, hashResult);
	//uint8_t* hashStruct = hash2Hex(hashResult);		// TODO : hashe le pointeur mais pas le contenu. Faire une fonction par type.


	//printf("hash struct : %s\n", hashStruct);


	free(hashFichier);
	free(hashStr);

	return EXIT_SUCCESS;
}