#pragma once
#include "common.h"

void writeKeysPEM(EVP_PKEY* key, const uint8_t* path);
EVP_PKEY* newEVP_PKEY(void);