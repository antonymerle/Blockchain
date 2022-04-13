#pragma once
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "common.h"

void writeKeysPEM(EVP_PKEY* key, const uint8_t* path);
EVP_PKEY* newEVP_PKEY(void);