#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <string>

#define NONCE_LEN 32

/*************************** General ***************************/

void error_msg();

#define FAIL(msg)    \
    std::cout << "ERROR: " << msg << std::endl; \
    fflush(stdout); \
    error_msg(); 

/*************************** Cipher ***************************/

int gcm_encrpyt(unsigned char *plaintext, int plaintext_len,
                unsigned char* aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);
        
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char* aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);

int gcm_authenticate(unsigned char* aad, int aad_len,
                     unsigned char* key, unsigned char* iv,
                     unsigned char* tag);

int gcm_verify(unsigned char *aad, int aad_len, 
               unsigned char *key, unsigned char *iv, unsigned char *tag);

void generate_random(unsigned char* buf, int size);

X509* get_certificate(std::string path);
int verify_certificate(X509* cacert, X509_CRL* crl, X509* srv_cert);

EVP_PKEY* generate_pubkey();

unsigned int sign(EVP_PKEY* priv_key, unsigned char* buf, unsigned int buf_len, unsigned char* signature);
int verify_signature(EVP_PKEY* pubkey, unsigned char* buf, unsigned int buf_len, unsigned char* signature, unsigned int sig_len);

int derive_shared_secret(EVP_PKEY* dhkey1, EVP_PKEY* dhkey2, unsigned char** skey);
unsigned int hash_secret(unsigned char* digest, unsigned char* skey, unsigned int skeylen);

void free_crypto(unsigned char* buf, size_t size);


