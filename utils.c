#include "utils.h"

uint8_t* concat(const uint8_t* strA, const uint8_t* strB)
{
	uint8_t* result;

	result = malloc(strlen(strA) + strlen(strB) + 1);	// +1 for the null terminator;
	if (result == NULL) exit(-1);

	strcpy(result, strA);
	strcat(result, strB);

	return result;
}
