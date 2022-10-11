#include "utils.h"
#include "crypto.h"
#include "Packet.h"
#include <string.h>

int readn(long fd, void *buf, size_t size){
    size_t left = size;
    int r;
    char *bufptr = (char*)buf;
    while(left>0) {
        if ((r=read((int)fd ,bufptr,left)) == -1) {
            if (errno == EINTR) continue;
            if (errno == ECONNRESET) return 0;
            return -1;
        }
        if (r == 0) return 0;   // gestione chiusura socket
        left    -= r;
        bufptr  += r;
    }
    return size;
}

int writen(long fd, void *buf, size_t size){
    size_t left = size;
    int r;
    char *bufptr = (char*)buf;
    while(left>0) {
        if ((r=write((int)fd ,bufptr,left)) == -1) {
            if (errno == EINTR) continue;
            if (errno == EPIPE) return 0;
            return -1;
        }
        if (r == 0) return 0;  
        left    -= r;
        bufptr  += r;
    }
    return 1;
}

int read_message(int fd, unsigned char* key, unsigned char** message){
    int err;
    unsigned char* request; NEW(request, new unsigned char[MSG_FRAGMENT], "new request");
    err = readn(fd, request, MSG_FRAGMENT);
    if (err <= 0){
        cout << "Fail to read request" << endl;
        delete [] request;
        return -1;
    }

    unsigned char* cphr_buf; NEW(cphr_buf, new unsigned char[CPHR_FRAGMENT], "new cphr buf");
    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* iv; NEW(iv, new unsigned char[IV_SIZE], "new iv");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(iv, request, IV_SIZE);
    memcpy(aads, iv, IV_SIZE);
    memcpy(cphr_buf, request + IV_SIZE, CPHR_FRAGMENT);
    memcpy(tag_buf, request + IV_SIZE + CPHR_FRAGMENT, TAG_SIZE);
    /*printf("IV received: \n");
    BIO_dump_fp (stdout, (const char *)iv, IV_SIZE);
    printf("Aads received: \n");
    BIO_dump_fp (stdout, (const char *)aads, AAD_FRAGMNENT);
    printf("Tag buf received: \n");
    BIO_dump_fp (stdout, (const char *)tag_buf, TAG_SIZE);
    printf("Cphr received: \n");
    BIO_dump_fp (stdout, (const char *)cphr_buf, CPHR_FRAGMENT);
    fflush(NULL);*/
    delete [] request;
    
    NEW(*message, new unsigned char[CLR_FRAGMENT], "new message");
    int pt_len = gcm_decrypt(cphr_buf, CLR_FRAGMENT, aads, AAD_FRAGMNENT, tag_buf, key, iv, IV_SIZE, *message);
    
    delete [] cphr_buf;
    delete [] tag_buf;
    delete [] iv;
    delete [] aads;
    if (pt_len == 0){
        // error in decrpytion
        cout << "Decrypt message fail (occhio alla lunghezza 0)" << endl;
        delete [] *message;
        return 0;
    }
    return pt_len;
}

int send_message(int fd, unsigned char* key, unsigned char* message){

    unsigned char* iv;  NEW(iv, new unsigned char[IV_SIZE], "new iv");
    generate_random(iv, IV_SIZE);
    int cphr_len, tag_len, err;

    unsigned char* cphr_buf; NEW(cphr_buf, new unsigned char[CPHR_FRAGMENT], "new cphr buf");
    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(aads, iv, IV_SIZE);

    cphr_len = gcm_encrpyt(message, CLR_FRAGMENT, aads, AAD_FRAGMNENT, key, iv, IV_SIZE, cphr_buf, tag_buf);
    if (cphr_len == 0){
        // Error while encrypting
        cout << "Ecnrypt message fail (occhio alla lunghezza 0)" << endl;
        delete [] cphr_buf;
        delete [] tag_buf;
        delete [] aads;
        delete [] iv;
        return 0;
    }

    unsigned char* request; NEW(request, new unsigned char[MSG_FRAGMENT], "new request");
    memcpy(request, iv, IV_SIZE);
    memcpy(request + IV_SIZE, cphr_buf, CPHR_FRAGMENT);
    memcpy(request + IV_SIZE + CPHR_FRAGMENT, tag_buf, TAG_SIZE);
    /*printf("IV sent: \n");
    BIO_dump_fp (stdout, (const char *)iv, IV_SIZE);
    printf("Aads sent: \n");
    BIO_dump_fp (stdout, (const char *)aads, AAD_FRAGMNENT);
    printf("Tag buf sent: \n");
    BIO_dump_fp (stdout, (const char *)tag_buf, TAG_SIZE);
    printf("Cphr sent: \n");
    BIO_dump_fp (stdout, (const char *)cphr_buf, CPHR_FRAGMENT);
    fflush(NULL);*/

    // Send to server the message
    err = writen(fd, request, MSG_FRAGMENT);

    delete [] cphr_buf;
    delete [] tag_buf;
    delete [] request;
    delete [] iv;
    delete [] aads;
    if(err <= 0) return 0;
    return cphr_len;
}

/**
* @brief Serializa a X509 into an unsigned char
*/
int serialize_certificate(int fd, X509* srv_cert, unsigned char** cert_buf){
    BIO* bio = BIO_new(BIO_s_mem());
    if(!bio){ cerr << "ERROR: Allocating bio" << endl; return 0; }
    if (1 != PEM_write_bio_X509(bio, srv_cert)) { 
        cerr << "ERROR: PEM_write_bio_X509" << endl;
        BIO_free(bio);
        return 0;
    }
    int cert_buf_len = BIO_ctrl_pending(bio);
    NEW(*cert_buf, new unsigned char[cert_buf_len], "pubkey serialization");
    if(BIO_read(bio, *cert_buf, cert_buf_len)<=0) { 
        cerr << "ERROR: BIO_read" << endl;
        delete [] *cert_buf;
        *cert_buf = NULL;
        cert_buf_len = 0;
    }
    BIO_free(bio);
    return cert_buf_len;
}

/**
* @brief Serializa a EVP_PKEY into an unsigned char
*/
int serialize_pubkey(int fd, EVP_PKEY* pubkey, unsigned char** pubkey_buf){
    BIO* bio = BIO_new(BIO_s_mem());
    if(!bio){ cerr << "ERROR: Allocating bio" << endl; return 0; }
    if (1 != PEM_write_bio_PUBKEY(bio, pubkey)) { 
        cerr << "ERROR: PEM_write_bio_PUBKEY" << endl;
        BIO_free(bio);
        return 0;
    }
    int pubkey_len = BIO_ctrl_pending(bio);
    NEW(*pubkey_buf, new unsigned char[pubkey_len], "pubkey serialization");
    if(BIO_read(bio, *pubkey_buf, pubkey_len)<=0) { 
        cerr << "ERROR: BIO_read" << endl;
        delete [] *pubkey_buf; *pubkey_buf = NULL;
        pubkey_len = 0;
    }
    BIO_free(bio);
    return pubkey_len;
}

X509* deserialize_certificate(unsigned char* srv_cert_buf, int srv_cert_len){
    BIO* bio = BIO_new(BIO_s_mem());
    if(!bio) { cerr << "ERROR: Allocating bio" << endl; return NULL; }

    if(BIO_write(bio, srv_cert_buf, srv_cert_len)<=0){ 
        cerr << "ERROR: BIO_write" << endl;
        BIO_free(bio);
        return NULL;
    }

    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    
    BIO_free(bio);
    return cert;
}

EVP_PKEY* deserialize_pubkey(unsigned char* srv_pubkey_buf, int srv_pubkey_len){
    BIO* bio = BIO_new(BIO_s_mem());
    if(!bio) { cerr << "ERROR: Allocating bio" << endl; return NULL; }

    if(BIO_write(bio, srv_pubkey_buf, srv_pubkey_len)<=0){ 
        cerr << "ERROR: BIO_write" << endl;
        BIO_free(bio);
        return NULL;
    }

    EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    
    BIO_free(bio);
    return pubkey;
}