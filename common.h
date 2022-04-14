#pragma once
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "defs.h"
#include "env.h"
#include "utils.h"


typedef struct {
	uint8_t nom[32];
	uint8_t prenom[32];
	size_t taille;
} Personne;