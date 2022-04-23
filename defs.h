#pragma once
#include "common.h"
	
typedef enum KEY_TYPE {
	PKEY,												// public key
	SKEY												// secret key
} KEY_TYPE;

typedef enum IO_BUFFER_SZ {
	READ_FILE_BUFFER_16K0_SZ = 1024 * 16,					// buffer to hash file
	HEX_HASH_NT_SZ = 65,									// SHA256 hexadecimal 64 + 1
	SIG_BIN_SZ = 256,										// SHA256 value calculated by openSSL EVP_DigestSignFinal()
	SIG_HEX_NT_SZ = (SIG_BIN_SZ * 2) + 1
} IO_BUFFER_SZ;