#pragma once

#include "common.h"

int signMsg(uint8_t signBin[SIG_BIN], EVP_PKEY* const skey, uint8_t* const msg);
int signFile(uint8_t signBin[SIG_BIN], EVP_PKEY* const skey, uint8_t* const filePath);
bool verifyStrMsg(EVP_PKEY* const pubkey, uint8_t* const signature, uint8_t* const msg);
bool verifyFileSignature(EVP_PKEY* const pubkey, uint8_t* const signature, uint8_t* const filePath);