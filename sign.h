#pragma once

#include "common.h"

uint8_t* signMsg(EVP_PKEY* skey, const uint8_t* msg);
uint8_t* signFile(EVP_PKEY* skey, const uint8_t* filePath);
bool verifyStrMsg(EVP_PKEY* pubkey, uint8_t* signature, uint8_t* msg);