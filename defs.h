#pragma once
#include "common.h"

#define READ_FILE_BUFFER_16K0		1024*16			// buffer to hash file
#define HEX_SHA256_NULLT_LEN		65				// 64 + 1
#define MAX_SIG_LENGTH				256

typedef enum {
	PKEY,		// public key
	SKEY		// secret key
} KEY_TYPE;