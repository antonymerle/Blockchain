#include <openssl/evp.h>
#include <openssl/applink.c>
#include "common.h"
#include "account.h"


int main(void)
{
	printf("Hello blockchain !\n");

	while (1)
	{
		EVP_PKEY* key = newEVP_PKEY();

		writeKeysPEM(key, DEBUG_PATH);

		EVP_PKEY_free(key);
	}

	return EXIT_SUCCESS;
}