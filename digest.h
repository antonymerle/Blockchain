#pragma once
#include "common.h"

int digest_hash_file(uint8_t hashBinResult[SHA256_DIGEST_LENGTH], uint8_t* const filePath);
int digest_hash_str(uint8_t binmd[SHA256_DIGEST_LENGTH], uint8_t* const str);									// 256 bits, 32 bytes
int digest_bin_2_hex(uint8_t hexmd[], IO_BUFFER_SZ OUT_SZ, uint8_t const binmd[], IO_BUFFER_SZ IN_SZ);
void digest_hex_pretty_print(uint8_t const hexsig[]);