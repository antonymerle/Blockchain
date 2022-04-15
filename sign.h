#pragma once

#include "common.h"

int signFile2(uint8_t signature[MAX_SIG_LENGTH], EVP_PKEY* skey, const uint8_t* filePath);
uint8_t* signFile(EVP_PKEY* skey, const uint8_t* md);