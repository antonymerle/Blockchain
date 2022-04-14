#pragma once
#include "common.h"

int hashFile(uint8_t hashBinResult[SHA256_DIGEST_LENGTH], uint8_t* filePath);
int hashData(uint8_t binmd[SHA256_DIGEST_LENGTH], uint8_t* data);			// 256 bits, 32 bytes
uint8_t* hash2Hex(uint8_t binaryHash[SHA256_DIGEST_LENGTH]);