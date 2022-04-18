#pragma once
#include "common.h"
	
typedef enum KEY_TYPE {
	PKEY,		// public key
	SKEY		// secret key
} KEY_TYPE;

typedef enum IO_BUFFER_SZ {
	READ_FILE_BUFFER_16K0 = 1024 * 16,									// buffer to hash file
	HEX_HASH_NT = 65,													// SHA256 hexadecimal 64 + 1
	SIG_BIN = 256,														// SHA256 value calculated by openSSL EVP_DigestSignFinal()
	SIG_HEX_NT = (SIG_BIN * 2) + 1
} IO_BUFFER_SZ;