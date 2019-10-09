#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>

int initCipher(void **, unsigned char *, unsigned char *, int);

int freeCipher(void *);

int encrypt(void *, unsigned char *, int *, unsigned char *, int, int);

#endif
