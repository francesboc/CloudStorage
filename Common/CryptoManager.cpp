#include "crypto.h"

const EVP_CIPHER* cipher = EVP_aes_128_gcm();
const EVP_MD* HASH_ALG = EVP_sha256();

void error_msg(){
    std::cerr << ERR_error_string(ERR_get_error(), NULL) << std::endl;
}

int gcm_encrpyt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag){
    EVP_CIPHER_CTX *ctx;
    int len=0;
    int ciphertext_len=0;
    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        FAIL("New cipher context");
        return -1;
    }
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv)){
        FAIL("Encrypt init");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){
        FAIL("Encrypt update aad");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
        FAIL("Encrypt update");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
	//Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len)){
        FAIL("Encrypt final");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)){
        FAIL("Encrypt ctrl");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        FAIL("Decrypt new ctx");
        return -1;
    }
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv)){
        FAIL("Decrypt init");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
	//Provide any AAD data.
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
        FAIL("Decrypt update aad");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
	//Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)){
        FAIL("Decrypt update");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)){
        FAIL("Decrypt ctrl");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        FAIL("Decrypt final");
        return -1;
    }
}

int gcm_authenticate(unsigned char* aad, int aad_len,
                     unsigned char* key, unsigned char* iv,
                     unsigned char* tag) {
    EVP_CIPHER_CTX *ctx;
    unsigned char* ciphertext;
    int len=0;
    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        FAIL("New cipher context");
        return 0;
    }
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv)){
        FAIL("Encrypt init");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){
        FAIL("Encrypt update aad");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

	//Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext, &len)){
        FAIL("Encrypt final");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)){
        FAIL("Encrypt ctrl");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int gcm_verify(unsigned char *aad, int aad_len, 
               unsigned char *key, unsigned char *iv, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    unsigned char* plaintext;
    int len;
    int ret;
    /* Create and initialize the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        FAIL("Decrypt new ctx");
        return 0;
    }
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv)){
        FAIL("Decrypt init");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
	//Provide any AAD data.
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
        FAIL("Decrypt update aad");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)){
        FAIL("Decrypt ctrl");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, plaintext, &len);

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);
    if(ret > 0) {
        return 1;
    } else {
        FAIL("Decrypt final");
        return 0;
    }

}
uint32_t sign(EVP_PKEY* priv_key, unsigned char* buf, uint32_t buf_len, unsigned char* signature){
    uint32_t signature_len = 0;
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){
        FAIL("New sign ctx");
        return 0;
    }
    if (EVP_SignInit(md_ctx, HASH_ALG) == 0){
        FAIL("Sign init");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    if (EVP_SignUpdate(md_ctx, buf, buf_len) == 0){
        FAIL("Sign update");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    if (EVP_SignFinal(md_ctx, signature, &signature_len, priv_key)==0){
        FAIL("Sign final");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    EVP_MD_CTX_free(md_ctx);
    return signature_len;
}

int verify_signature(EVP_PKEY* pubkey, unsigned char* buf, uint32_t buf_len, unsigned char* signature, uint32_t sig_len){
    int err;
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    // AD ogni return libera il context
    if(!md_ctx){
        FAIL("Verify sign ctx new");
        return 0;
    }
    if (EVP_VerifyInit(md_ctx, HASH_ALG)==0){
        FAIL("Verify sign init");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    if (EVP_VerifyUpdate(md_ctx, buf, buf_len)==0){
        FAIL("Verify sign update");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    err = EVP_VerifyFinal(md_ctx, signature, sig_len, pubkey);
    if(err <= 0){
        FAIL("Verify sign final");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }
    EVP_MD_CTX_free(md_ctx);
    return 1;
}

void generate_random(unsigned char* buf, int size){
    RAND_poll();
    RAND_bytes(buf, size);
}

X509* get_certificate(std::string path){
    FILE* fp = fopen(path.c_str(), "r");
    if(!fp){
        perror("open file");
        return NULL;
    }

    X509* srv_cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if(!srv_cert){ FAIL("read certificate"); }
    
    fclose(fp);
    return srv_cert;
}

int verify_certificate(X509* cacert, X509_CRL* crl, X509* srv_cert){
    int ret;
    X509_STORE* store = X509_STORE_new();
    if(!store){ FAIL("X509_STORE_new returned NULL"); return 0; }
    ret = X509_STORE_add_cert(store, cacert);
    if(ret != 1) { FAIL("X509_STORE_add_cert"); X509_STORE_free(store); return 0; }
    ret = X509_STORE_add_crl(store, crl);
    if(ret != 1) { FAIL("X509_STORE_add_crl"); X509_STORE_free(store); return 0; }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) { FAIL("X509_STORE_set_flags"); X509_STORE_free(store); return 0; }

    // verify the certificate:
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) { FAIL("X509_STORE_CTX_new returned NULL"); X509_STORE_free(store); return 0; }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, srv_cert, NULL);
    if(ret != 1) { FAIL("X509_STORE_CTX_init"); X509_STORE_free(store); X509_STORE_CTX_free(certvfy_ctx); return 0; }
    ret = X509_verify_cert(certvfy_ctx);
    
    X509_STORE_free(store);
    X509_STORE_CTX_free(certvfy_ctx);
    if(ret != 1){ FAIL("X509_verify_cert"); return 0; }
    return ret;
}

EVP_PKEY* generate_pubkey(){
    EVP_PKEY *params = EVP_PKEY_new();
    if (!params) return NULL;
    EVP_PKEY_CTX *DHctx;
    if(!(DHctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))){
        FAIL("ECDH new id");
        EVP_PKEY_free(params);
        return NULL;
    }
    if(1 != EVP_PKEY_paramgen_init(DHctx)){
        FAIL("ECDH paramgen init");
        EVP_PKEY_CTX_free(DHctx);
        EVP_PKEY_free(params);
        return NULL;
    }
    if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(DHctx, NID_X9_62_prime256v1)){
        FAIL("ECDH paramgen curve nid");
        EVP_PKEY_CTX_free(DHctx);
        EVP_PKEY_free(params);
        return NULL;
    }
    if(1 != EVP_PKEY_paramgen(DHctx, &params)){
        FAIL("ECDH paramgen");
        EVP_PKEY_CTX_free(DHctx);
        EVP_PKEY_free(params);
        return NULL;
    }
    /* Generate a new key */
    EVP_PKEY *my_dhkey = NULL;
    if(1 != EVP_PKEY_keygen_init(DHctx)){
        FAIL("ECDH keygen init");
        EVP_PKEY_CTX_free(DHctx);
        EVP_PKEY_free(params);
        return NULL;
    }
    if(1 != EVP_PKEY_keygen(DHctx, &my_dhkey)) { FAIL("ECDH keygen"); }

    EVP_PKEY_CTX_free(DHctx);
    EVP_PKEY_free(params);
    return my_dhkey;
}

uint32_t derive_shared_secret(EVP_PKEY* dhkey1, EVP_PKEY* dhkey2, unsigned char** skey){
    EVP_PKEY_CTX *derive_ctx;
    size_t skeylen;
    derive_ctx = EVP_PKEY_CTX_new(dhkey1,NULL);
    if (!derive_ctx){ FAIL("Derive ECDH ctx"); return 0; }
    if (EVP_PKEY_derive_init(derive_ctx) <= 0){ FAIL("Derive ECDH init"); EVP_PKEY_CTX_free(derive_ctx); return 0; }
    /*Setting the peer with its pubkey*/
    if (EVP_PKEY_derive_set_peer(derive_ctx, dhkey2) <= 0){ FAIL("Derive ECDH set peer"); EVP_PKEY_CTX_free(derive_ctx); return 0; }
    /* Determine buffer length, by performing a derivation but writing the result nowhere */
    if (EVP_PKEY_derive(derive_ctx, NULL, &skeylen) <= 0){ FAIL("Derive ECDH derive len"); EVP_PKEY_CTX_free(derive_ctx); return 0; }
    /*allocate buffer for the shared secret*/
    try{
        *skey = new unsigned char[(int(skeylen))];
    }
    catch(std::bad_alloc){
        std::cout << "Error while allocating secret key" <<  std::endl;
        exit(EXIT_FAILURE);
    }
    /*Perform again the derivation and store it in skey buffer*/
    if (EVP_PKEY_derive(derive_ctx, *skey, &skeylen) <= 0){ 
        FAIL("Derive ECDH derive");
        delete[] *skey;
        skeylen = 0;
    }
    EVP_PKEY_CTX_free(derive_ctx);
    return skeylen;
}

uint32_t hash_secret(unsigned char* digest, unsigned char* skey, uint32_t skeylen){
    uint32_t digestlen;	
    // Create and init context
    EVP_MD_CTX *Hctx;
    Hctx = EVP_MD_CTX_new();
    if(!Hctx) { FAIL("New hash ctx"); return 0; }
    //check errors
    if (EVP_DigestInit(Hctx, HASH_ALG) !=1 ) { FAIL("Digest init"); EVP_MD_CTX_free(Hctx); return 0; }
    if (EVP_DigestUpdate(Hctx, (unsigned char*)skey, skeylen) != 1) { FAIL("Digest update"); EVP_MD_CTX_free(Hctx); return 0; }
    if (EVP_DigestFinal(Hctx, digest, &digestlen) != 1) { 
        FAIL("Digest final");
        digestlen = 0;
    }
    EVP_MD_CTX_free(Hctx);
    return digestlen;
}

void free_crypto(unsigned char* buf, size_t size){
#pragma optimize("", off)
    memset(buf, 0, size);
#pragma optmize("", on)
    delete [] buf;
}