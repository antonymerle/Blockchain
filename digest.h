#pragma once
#include "common.h"

int digest_hash_file(uint8_t hashBinResult[SHA256_DIGEST_LENGTH], uint8_t* const filePath);
int digest_hash_str(uint8_t binmd[SHA256_DIGEST_LENGTH], uint8_t* const str);									// 256 bits, 32 bytes
int digest_bin_2_hex(uint8_t hexmd[HEX_HASH_NT_SZ], IO_BUFFER_SZ OUT_SZ, uint8_t const binmd[SHA256_DIGEST_LENGTH], IO_BUFFER_SZ IN_SZ);		// TODO : simplifier : lock buffer size, suppress arg 2 & 4
int digest_hex_2_bin(uint8_t binmd[], IO_BUFFER_SZ OUT_SZ, uint8_t const hexmd[], IO_BUFFER_SZ IN_SZ);
void digest_hex_pretty_print(uint8_t const hexsig[]);

int digest_pair_bin_leaves(LeavesPair* lp, uint8_t left[SHA256_DIGEST_LENGTH], uint8_t right[SHA256_DIGEST_LENGTH]);
int digest_hash_bin_pair_leaves(uint8_t bin_hash_result[SHA256_DIGEST_LENGTH], LeavesPair* const lp);
int digest_hash_merkle_proof(uint8_t binmd[SHA256_DIGEST_LENGTH], uint8_t* const tx_hash_buffer_bin, size_t buffer_size);
int digest_merkle_root(uint8_t merkle_root[SHA256_DIGEST_LENGTH], size_t leaves_number, uint8_t leaves_bin[]);

int digest_wb32_file(uint8_t* const path, size_t sz, uint8_t* bin_buffer);
int digest_wb64_file(uint8_t* const path, size_t sz, LeavesPair* lp);