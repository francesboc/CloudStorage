#if !defined(_UTILS_H_)
#define _UTILS_H_
#include <iostream>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <openssl/evp.h>

#define TAG_SIZE 16
#define CPHR_FRAGMENT 256
#define CLR_FRAGMENT 240
#define AAD_FRAGMNENT 64
#define MSG_FRAGMENT 512
#define IV_SIZE 12
#define USRNM_LEN 32

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
    /*      operazioni che il server deve gestire */
    /* ------------------------------------------ */
    UPLOAD          = 12,
    UPLOAD_REQ      = 0,   /// richiesta di registrazione di un ninckname
    UPLOAD_FRGM     = 10,
    UPLOAD_END      = 11,
    UPLOAD_DONE     = 13,
    DOWNLOAD        = 1,   /// richiesta di connessione di un client
    DELETE          = 2,   /// richiesta di invio di un messaggio testuale ad un nickname o groupname
    DELETE_REQ      = 101,
    DELETE_CONFIRM  = 102,
    DELETE_OK       = 103,
    DELETE_ABORT    = 104,
    LIST            = 3,   /// richiesta di invio di un messaggio testuale a tutti gli utenti 
    LIST_REQ        = 6,
    LIST_RSP        = 7,
    LIST_DONE       = 8, 
    RENAME          = 201,
    RENAME_REQ      = 202,
    RENAME_OK       = 203,   /// richiesta di invio di un file ad un nickname o groupname
    LOGOUT          = 5,   /// richiesta di recupero di un file
    HELP            = 105,
    /* ------------------------------------------ */
    /*    messaggi inviati dal server             */
    /* ------------------------------------------ */
    HANDSHAKE_REQ   = 20,  // operazione eseguita con successo    
    HANDSHAKE_PH1   = 21,  // notifica di messaggio testuale
    HANDSHAKE_PH2   = 22,  // notifica di messaggio "file disponibile"
    HANDSHAKE_PH3   = 23,
    HANDSHAKE_ERR   = 24,
    /* ------------------------------------------ */
    /*    error codes                             */
    /* ------------------------------------------ */
    ERROR_MSGS      = 40,
    SRV_ERROR       = 401,
    RENEW_KEY       = 402,
    OP_FAIL         = 41,  // generico messaggio di fallimento
    CLIENT_EOF      = 42,  // client reach EOF or crashed
    OP_NICK_ALREADY = 26,  // nickname o groupname gia' registrato
    OP_NICK_UNKNOWN = 27,  // nickname non riconosciuto
    OP_MSG_TOOLONG  = 28,  // messaggio con size troppo lunga
    NO_SUCH_FILE = 29,  // il file richiesto non esiste
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
command_t read_data_message(int fd, unsigned char* key, unsigned char* plaintext, int* pt_len, int *seq_number);

command_t my_read_message(int fd, unsigned char* key, unsigned char** message, int* seq_number, int* nmessages);
int my_send_message(int fd, unsigned char* key, command_t msg_type, string message, int* seq_number, int nmessages);
int send_authenticated_msg(int fd, unsigned char* key, command_t msg_type, int* seq_number);
command_t read_authenticated_msg(int fd, unsigned char* key, int* seq_number);

int serialize_certificate(int fd, X509* srv_cert, unsigned char** cert_buf);
int serialize_pubkey(int fd, EVP_PKEY* pubkey, unsigned char** pubkey_buf);
X509* deserialize_certificate(unsigned char* srv_cert_buf, int srv_cert_len);
EVP_PKEY* deserialize_pubkey(unsigned char* srv_pubkey_buf, int srv_pubkey_len);



#endif /* _UTILS_H_ */