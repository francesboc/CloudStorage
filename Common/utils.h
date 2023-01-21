#if !defined(_UTILS_H_)
#define _UTILS_H_
#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <openssl/evp.h>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <map>

#define TAG_SIZE 16
#define CPHR_FRAGMENT 256
#define CLR_FRAGMENT 240
#define AAD_FRAGMNENT 64
#define MSG_FRAGMENT 512
#define IV_SIZE 12
#define USRNM_LEN 32
#define FILENAME_SIZE 128
#define MAX_FRAGMENT_SIZE (1024*1024)
#define DOWNLOAD_PROGRESS 100
// (ratio betwenn seq number space and max fragment size) + limit -> 2^32/2^20 + 100
#define UPDATE_KEY_LIMIT 4196 

using namespace std;

#define NEW(var, object, errmsg)    \
    try{                            \
        var = object;               \
    }                               \
    catch(bad_alloc){               \
        cout << "Error while allocating " << errmsg <<  endl; \
        exit(EXIT_FAILURE);         \
    }                               \

/**
 * @file  ops.h
 * @brief It contains operational request/response code
 */
typedef enum {
    /* ------------------------------------------ */
    /*          Cloud Storage operations          */
    /* ------------------------------------------ */
    UPLOAD          = 10,
    UPLOAD_REQ      = 11,   
    UPLOAD_ACK      = 12,
    UPLOAD_FRGM     = 13,
    UPLOAD_END      = 14,
    UPLOAD_DONE     = 15,

    DOWNLOAD        = 20, 
    DOWNLOAD_REQ    = 21,
    DOWNLOAD_ACK    = 22,
    DOWNLOAD_FRGM   = 23,
    DOWNLOAD_END    = 24,
    DOWNLOAD_DONE   = 25,

    DELETE          = 30,
    DELETE_REQ      = 31,
    DELETE_CONFIRM  = 32,
    DELETE_OK       = 33,
    DELETE_ABORT    = 34,

    LIST            = 40,
    LIST_REQ        = 41,
    LIST_RSP        = 42,
    LIST_DONE       = 43,

    RENAME          = 50,
    RENAME_REQ      = 51,
    RENAME_ACK      = 52,
    RENAME_OK       = 53,
    RENAME_FAIL     = 54,

    LOGOUT          = 60,

    HELP            = 70,
    /* ------------------------------------------ */
    /*          handshake messages                */
    /* ------------------------------------------ */
    HANDSHAKE_REQ   = 100,
    HANDSHAKE_PH1   = 101,
    HANDSHAKE_PH2   = 102,
    HANDSHAKE_PH3   = 103,
    HANDSHAKE_ERR   = 104,

    UPDATE_KEY_REQ  = 200,
    UPDATE_KEY_ACK  = 201,
    /* ------------------------------------------ */
    /*          error codes                       */
    /* ------------------------------------------ */
    SRV_ERROR       = 301,
    RENEW_KEY       = 302,
    OP_FAIL         = 303,
    CLIENT_EOF      = 304, 
    OP_NICK_ALREADY = 305, 
    OP_NICK_UNKNOWN = 306, 
    NO_SUCH_FILE    = 308, 
    NOT_VALID_FILE  = 309,
    FILE_ALREADY    = 310,
} command_t;

/**
 * @brief Socket management functions
 */

int readn(long fd, void *buf, size_t size);
int writen(long fd, void *buf, size_t size);
int send_data(int fd, unsigned char* message, int len);
int read_data(int fd, unsigned char** message, int* len);
int send_udata(int fd, unsigned char* message, unsigned int len);
int read_udata(int fd, unsigned char** message, unsigned int* len);

command_t read_message(int fd, unsigned char* key, string &plaintext, uint32_t *seq_number);
int send_message(int fd, unsigned char* key, command_t msg_type, string message, uint32_t* seq_number);
int send_data_message(int fd, unsigned char* key, command_t msg_type, unsigned char* plaintext, unsigned int pt_len, uint32_t* seq_number);
command_t read_data_message(int fd, unsigned char* key, unsigned char** plaintext, int* pt_len, uint32_t *seq_number);
int send_authenticated_msg(int fd, unsigned char* key, command_t msg_type, uint32_t* seq_number);
command_t read_authenticated_msg(int fd, unsigned char* key, uint32_t* seq_number);

/**
 * @brief Handshake management functions
 */

unsigned int serialize_certificate(int fd, X509* srv_cert, unsigned char** cert_buf);
unsigned int serialize_pubkey(int fd, EVP_PKEY* pubkey, unsigned char** pubkey_buf);
X509* deserialize_certificate(unsigned char* srv_cert_buf, unsigned int srv_cert_len);
EVP_PKEY* deserialize_pubkey(unsigned char* srv_pubkey_buf, unsigned int srv_pubkey_len);

/**
 * @brief Utility functions
 */

void error_msg_type(string msg, command_t msg_type);
bool check_string(string s1);
bool strictly_check_string(string s1);
bool canonicalize1(string file, string username);
bool unsigned_math(string op, unsigned int a, unsigned int b, unsigned int* result);


#endif /* _UTILS_H_ */