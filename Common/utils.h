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

#define TAG_SIZE 16
#define CPHR_FRAGMENT 256
#define CLR_FRAGMENT 240
#define AAD_FRAGMNENT 64
#define MSG_FRAGMENT 512
#define IV_SIZE 12
#define USRNM_LEN 32
#define MAX_FRAGMENT_SIZE (1024*1024)
#define DOWNLOAD_PROGRESS 100
// based on max fragment size -> 2^32/2^20 + 100
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
 * @brief Contiene i codici delle operazioni di richiesta e risposta
 */
typedef enum {
    /* ------------------------------------------ */
    /*      Cloud Storage operations              */
    /* ------------------------------------------ */
    UPLOAD          = 10,
    UPLOAD_REQ      = 11,   /// richiesta di registrazione di un ninckname
    UPLOAD_FRGM     = 12,
    UPLOAD_END      = 13,
    UPLOAD_DONE     = 14,

    DOWNLOAD        = 20,   /// richiesta di connessione di un client
    DOWNLOAD_REQ    = 21,
    DOWNLOAD_OK     = 22,
    DOWNLOAD_FRGM   = 23,
    DOWNLOAD_END    = 24,
    DOWNLOAD_DONE   = 25,

    DELETE          = 30,   /// richiesta di invio di un messaggio testuale ad un nickname o groupname
    DELETE_REQ      = 31,
    DELETE_CONFIRM  = 32,
    DELETE_OK       = 33,
    DELETE_ABORT    = 34,

    LIST            = 40,   /// richiesta di invio di un messaggio testuale a tutti gli utenti 
    LIST_REQ        = 41,
    LIST_RSP        = 42,
    LIST_DONE       = 43,

    RENAME          = 50,
    RENAME_REQ      = 51,
    RENAME_OK       = 52,   /// richiesta di invio di un file ad un nickname o groupname

    LOGOUT          = 60,   /// richiesta di recupero di un file

    HELP            = 70,
    /* ------------------------------------------ */
    /*    handshake messages                      */
    /* ------------------------------------------ */
    HANDSHAKE_REQ   = 100,  // operazione eseguita con successo    
    HANDSHAKE_PH1   = 101,  // notifica di messaggio testuale
    HANDSHAKE_PH2   = 102,  // notifica di messaggio "file disponibile"
    HANDSHAKE_PH3   = 103,
    HANDSHAKE_ERR   = 104,

    UPDATE_KEY_REQ  = 200,
    UPDATE_KEY_ACK  = 201,
    /* ------------------------------------------ */
    /*    error codes                             */
    /* ------------------------------------------ */
    ERROR_MSGS      = 300,
    SRV_ERROR       = 301,
    RENEW_KEY       = 302,
    OP_FAIL         = 303,  // generico messaggio di fallimento
    CLIENT_EOF      = 304,  // client reach EOF or crashed
    OP_NICK_ALREADY = 305,  // nickname o groupname gia' registrato
    OP_NICK_UNKNOWN = 306,  // nickname non riconosciuto
    OP_MSG_TOOLONG  = 307,  // messaggio con size troppo lunga
    NO_SUCH_FILE    = 308,  // il file richiesto non esiste
    NOT_VALID_FILE  = 309,
} command_t;

/**
 * @brief Socket management functions
 */

int readn(long fd, void *buf, size_t size);
int writen(long fd, void *buf, size_t size);
int send_data(int fd, unsigned char* message, int len);
int read_data(int fd, unsigned char** message, int* len);
command_t read_message(int fd, unsigned char* key, string &plaintext, int *seq_number);
int send_message(int fd, unsigned char* key, command_t msg_type, string message, int* seq_number);
int send_data_message(int fd, unsigned char* key, command_t msg_type, unsigned char* plaintext, int pt_len, int* seq_number);
command_t read_data_message(int fd, unsigned char* key, unsigned char** plaintext, int* pt_len, int *seq_number);

command_t my_read_message(int fd, unsigned char* key, unsigned char** message, int* seq_number, int* nmessages);
int my_send_message(int fd, unsigned char* key, command_t msg_type, string message, int* seq_number, int nmessages);
int send_authenticated_msg(int fd, unsigned char* key, command_t msg_type, int* seq_number);
command_t read_authenticated_msg(int fd, unsigned char* key, int* seq_number);

int serialize_certificate(int fd, X509* srv_cert, unsigned char** cert_buf);
int serialize_pubkey(int fd, EVP_PKEY* pubkey, unsigned char** pubkey_buf);
X509* deserialize_certificate(unsigned char* srv_cert_buf, int srv_cert_len);
EVP_PKEY* deserialize_pubkey(unsigned char* srv_pubkey_buf, int srv_pubkey_len);

void error_msg_type(string msg, command_t msg_type);

#endif /* _UTILS_H_ */