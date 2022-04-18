#pragma once
#include "common.h"

int hash2Hex(uint8_t hexmd[HEX_HASH_NT], uint8_t binmd[SHA256_DIGEST_LENGTH]);				// deprecated

int hashFile(uint8_t hashBinResult[SHA256_DIGEST_LENGTH], uint8_t* filePath);
int hashStr(uint8_t binmd[SHA256_DIGEST_LENGTH], uint8_t* str);									// 256 bits, 32 bytes
int bin2Hex(uint8_t hexmd[], IO_BUFFER_SZ SZ, uint8_t binmd[256]);