#pragma once
#include "common.h"

EVP_PKEY* newEVP_PKEY(void);
int writeKeysPEM(EVP_PKEY* const key, uint8_t* const path);
int loadKeyFromPEMFile(EVP_PKEY** const key, uint8_t* const filePath);
void print_PEM_key(EVP_PKEY* const key, KEY_TYPE KT);
void print_PEM_keys(EVP_PKEY* const key);
