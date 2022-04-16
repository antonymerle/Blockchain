#pragma once

#include "common.h"

int signFile2(uint8_t signature[MAX_SIG_LENGTH], EVP_PKEY* skey, const uint8_t* filePath);				// deprecated
uint8_t* signMsg(EVP_PKEY* skey, const uint8_t* msg);
uint8_t* signMsg2(EVP_PKEY* skey, const uint8_t* msg);
bool verifyStrMsg(EVP_PKEY* pubkey, uint8_t* signature, uint8_t* msg);