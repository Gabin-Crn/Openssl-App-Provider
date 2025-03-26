#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>

int main() {
    OSSL_PROVIDER *provider = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char key[32] = "01234567890123456789012345678901";
    unsigned char iv[16] = "0123456789012345";
    char intext[] = "Some Crypto Text";
    unsigned char outbuf[1024];
    int outlen, tmplen;


    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        fprintf(stderr, "No Context\n");
        return EXIT_FAILURE;
    }

    // Load the provider
    provider = OSSL_PROVIDER_load(NULL, "C:\\LegacyApp\\OpenSSL-Win64\\lib\\ossl_modules\\libmyProvider");
    if (provider == NULL) {
        fprintf(stderr, "Erreur: Impossible de charger le provider.\n");
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    printf("Provider are loaded with success !\n");

    // Retrieve Cipher
    cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", "provider=MyProvider");
    if (cipher == NULL) {
        fprintf(stderr, "Failed to fetch AES-256-CBC\n");
        OSSL_PROVIDER_unload(provider);
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    printf("Cipher successfully loaded\n");

    printf("Key: ");
    for (int i = 0; i < 32; i++) printf("%02X ", key[i]);
    printf("\n");

    printf("IV: ");
    for (int i = 0; i < 16; i++) printf("%02X ", iv[i]);
    printf("\n");


    // Encrypt Initialisation

    if (!EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1)) {

        fprintf(stderr, "Failed to EVP_EncryptInit\n");
        EVP_CIPHER_free(cipher);
        OSSL_PROVIDER_unload(provider);
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    memset(outbuf, 0, sizeof(outbuf));

    // Encrypt data
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, intext, strlen(intext))) {
        fprintf(stderr, "Failed to EVP_EncryptUpdate\n");
        EVP_CIPHER_free(cipher);
        OSSL_PROVIDER_unload(provider);
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    if (!EVP_EncryptFinal(ctx, outbuf + outlen, &tmplen)) {
        fprintf(stderr, "Failed to EVP_EncryptFinal\n");
        EVP_CIPHER_free(cipher);
        OSSL_PROVIDER_unload(provider);
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    outlen += tmplen;
    printf("Initial message : \"%s\"\n", (char *)intext);
    printf("Message shifted by one bit : \"%s\"\n", (char *)outbuf);

    // Free Ressources
    EVP_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(provider);
    EVP_CIPHER_CTX_free(ctx);

    return EXIT_SUCCESS;
}
