#pragma once
#include "common.h"

int hashFile(uint8_t hashBinResult[SHA256_DIGEST_LENGTH], uint8_t* filePath);
int hashStr(uint8_t binmd[SHA256_DIGEST_LENGTH], uint8_t* str);			// 256 bits, 32 bytes
int hash2Hex(uint8_t hexmd[HEX_SHA256_NULLT_LEN], uint8_t binmd[SHA256_DIGEST_LENGTH]);