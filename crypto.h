#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <string.h>

struct encryptor {
  void *encryptCtx;
  void *decryptCtx;
  int sentIv;
  int receivedIv;
};

int freeCipher(struct encryptor *);

int encrypt(struct encryptor *, unsigned char *, int *, unsigned char *, int,
            unsigned char *, unsigned char *);

int decrypt(struct encryptor *, unsigned char *, int *, unsigned char *, int,
            unsigned char *, unsigned char *);

int encryptOnce(struct encryptor *, unsigned char *, int *, unsigned char *,
                int, unsigned char *, unsigned char *);

int decryptOnce(struct encryptor *, unsigned char *, int *, unsigned char *,
                int, unsigned char *, unsigned char *);

#endif
