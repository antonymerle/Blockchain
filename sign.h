#pragma once

#include "common.h"

int signMsg(uint8_t signBin[SIG_BIN], EVP_PKEY* skey, const uint8_t* msg);
int signFile(uint8_t signBin[SIG_BIN], EVP_PKEY* skey, const uint8_t* filePath);
bool verifyStrMsg(EVP_PKEY* pubkey, uint8_t* signature, uint8_t* msg);
bool verifyFileSignature(EVP_PKEY* pubkey, uint8_t* signature, uint8_t* filePath);