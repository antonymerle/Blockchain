#pragma once
#include "common.h"

EVP_PKEY* newEVP_PKEY(void);
int writeKeysPEM(EVP_PKEY* const key, const uint8_t* path);
int loadKeyFromPEMFile(EVP_PKEY** skey, const uint8_t* filePath);
void print_PEM_key(EVP_PKEY* key, KEY_TYPE KT);
void print_PEM_keys(EVP_PKEY* key);
