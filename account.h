#pragma once
#include "common.h"

EVP_PKEY* newEVP_PKEY(void);
void writeKeysPEM(EVP_PKEY* key, const uint8_t* path);
int loadKeyFromPEMFile(EVP_PKEY** skey, const uint8_t* filePath);

//TODO : EVP_PKEY_print_private / public