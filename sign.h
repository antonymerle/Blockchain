#pragma once

#include "common.h"

int signFile(uint8_t signature[MAX_SIG_LENGTH], EVP_PKEY* skey, const uint8_t* filePath);