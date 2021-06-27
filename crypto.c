#include "crypto.h"

#include <assert.h>

int freeCipher(struct encryptor *encryptor) {
  EVP_CIPHER_CTX_free(encryptor->encryptCtx);
  EVP_CIPHER_CTX_free(encryptor->decryptCtx);
}

static int initCipher(void **ctx, unsigned char *key, unsigned char *iv,
                      int encryptFlag) {

  if (!(*ctx = (EVP_CIPHER_CTX *)EVP_CIPHER_CTX_new()))
    return -1;

  if (1 != (encryptFlag == 1 ? EVP_EncryptInit_ex : EVP_DecryptInit_ex)(
               (EVP_CIPHER_CTX *)*ctx, EVP_aes_256_cfb128(), NULL, key, iv))
    return -1;

  return 0;
}

static int _encrypt(void *ctx, unsigned char *desttext, int *desttext_len,
                    unsigned char *sourcetext, int sourcetext_len,
                    int encryptFlag) {
// Uncomment this to cancel encrypt/decrypt, for debug purpose.
//  *desttext_len = sourcetext_len;
//   memcpy(desttext, sourcetext, sourcetext_len);
//   return 0;

  if (1 != (encryptFlag == 1 ? EVP_EncryptUpdate : EVP_DecryptUpdate)(
               (EVP_CIPHER_CTX *)ctx, desttext, desttext_len, sourcetext,
               sourcetext_len)) {
    return -1;
  }
  return 0;
}

int encrypt(struct encryptor *encryptor, unsigned char *desttext,
            int *desttext_len, unsigned char *sourcetext, int sourcetext_len,
            unsigned char *key, unsigned char *iv) {

  if (encryptor->sentIv == 0) {
    if (initCipher((void **)&encryptor->encryptCtx, key, iv, 1) == -1) {
      perror("initCipher, encrypt");
      exit(EXIT_FAILURE);
    }
    encryptor->sentIv = 1;

    memcpy(desttext, iv, 16);
    _encrypt(encryptor->encryptCtx, desttext + 16, desttext_len, sourcetext,
             sourcetext_len, 1);
    *desttext_len += 16;
    return 0;
  } else {
    assert(encryptor->encryptCtx != NULL);

    return _encrypt(encryptor->encryptCtx, desttext, desttext_len, sourcetext,
                    sourcetext_len, 1);
  }
}

int decrypt(struct encryptor *encryptor, unsigned char *desttext,
            int *desttext_len, unsigned char *sourcetext, int sourcetext_len,
            unsigned char *key, unsigned char *iv) {

  unsigned char *receivedIv;

  if (encryptor->receivedIv == 0) {
    receivedIv = sourcetext;

    if (initCipher((void **)&encryptor->decryptCtx, key, receivedIv, 0) == -1) {
      perror("initCipher, decrypt");
      exit(EXIT_FAILURE);
    }

    encryptor->receivedIv = 1;

    return _encrypt(encryptor->decryptCtx, desttext, desttext_len,
                    sourcetext + 16, sourcetext_len - 16, 0);
  } else {
    assert(encryptor->decryptCtx != NULL);

    return _encrypt(encryptor->decryptCtx, desttext, desttext_len, sourcetext,
                    sourcetext_len, 0);
  }
}

int encryptOnce(struct encryptor *encryptor, unsigned char *desttext,
                int *desttext_len, unsigned char *sourcetext,
                int sourcetext_len, unsigned char *key, unsigned char *iv) {
  int s;
  s = encrypt(encryptor, desttext, desttext_len, sourcetext, sourcetext_len,
              key, iv);

  encryptor->sentIv = 0;

  EVP_CIPHER_CTX_free(encryptor->encryptCtx);
  encryptor->encryptCtx = NULL;

  return s;
}

int decryptOnce(struct encryptor *encryptor, unsigned char *desttext,
                int *desttext_len, unsigned char *sourcetext,
                int sourcetext_len, unsigned char *key, unsigned char *iv) {
  int s;
  s = decrypt(encryptor, desttext, desttext_len, sourcetext, sourcetext_len,
              key, iv);

  encryptor->receivedIv = 0;

  EVP_CIPHER_CTX_free(encryptor->decryptCtx);
  encryptor->decryptCtx = NULL;

  return s;
}
