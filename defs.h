#pragma once
#include "common.h"

#define TPS_MAX		32*32*8									// bytes*transactions*minutes

typedef enum KEY_TYPE {
	PKEY,													// public key
	SKEY													// secret key
} KEY_TYPE;

typedef enum IO_BUFFER_SZ {
	READ_FILE_BUFFER_16K0_SZ = 1024 * 16,					// buffer to hash file
	HEX_HASH_NT_SZ = 65,									// SHA256 hexadecimal 64 + 1
	SIG_BIN_SZ = 256,										// SHA256 value calculated by openSSL EVP_DigestSignFinal()
	SIG_HEX_NT_SZ = (SIG_BIN_SZ * 2) + 1
} IO_BUFFER_SZ;


typedef struct Account {
	EVP_PKEY* keys;
	uint64_t transactions;									// TODO: mettre également une liste de transactions ? Linked List ?
	uint64_t received;
	uint64_t sent;
	uint64_t balance;
} Account;


typedef struct Transaction {
	uint8_t id[SHA256_DIGEST_LENGTH];
} Transaction;

typedef struct LeavesPair {
	uint8_t left[SHA256_DIGEST_LENGTH];
	uint8_t right[SHA256_DIGEST_LENGTH];
} LeavesPair;