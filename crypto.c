#include "crypto.h"

int initCipher(void **ctx, unsigned char *key, unsigned char *iv,
               int encryptFlag) {
  if (!(*ctx = (EVP_CIPHER_CTX *)EVP_CIPHER_CTX_new()))
    return -1;

  if (1 != (encryptFlag == 1 ? EVP_EncryptInit_ex : EVP_DecryptInit_ex)(
               (EVP_CIPHER_CTX *)*ctx, EVP_aes_256_cfb8(), NULL, key, iv))
    return -1;

  return 0;
}

int freeCipher(void *ctx) { EVP_CIPHER_CTX_free(ctx); }

int encrypt(void *ctx, unsigned char *desttext, int *desttext_len,
            unsigned char *sourcetext, int sourcetext_len, int encryptFlag) {
  //*desttext_len = sourcetext_len;
  // memcpy(desttext, sourcetext, sourcetext_len);
  // return 0;

  if (1 != (encryptFlag == 1 ? EVP_EncryptUpdate : EVP_DecryptUpdate)(
               (EVP_CIPHER_CTX *)ctx, desttext, desttext_len, sourcetext,
               sourcetext_len)) {
    return -1;
  }
  return 0;
}
