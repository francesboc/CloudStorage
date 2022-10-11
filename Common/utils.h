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
    UPLOAD          = 0,   /// richiesta di registrazione di un ninckname
    DOWNLOAD        = 1,   /// richiesta di connessione di un client
    DELETE          = 2,   /// richiesta di invio di un messaggio testuale ad un nickname o groupname
    LIST            = 3,   /// richiesta di invio di un messaggio testuale a tutti gli utenti 
    RENAME          = 4,   /// richiesta di invio di un file ad un nickname o groupname
    LOGOUT          = 5,   /// richiesta di recupero di un file
    /* ------------------------------------------ */
    /*    messaggi inviati dal server             */
    /* ------------------------------------------ */
    HANDSHAKE_REQ   = 20,  // operazione eseguita con successo    
    HANDSHAKE_PH1   = 21,  // notifica di messaggio testuale
    HANDSHAKE_PH2   = 22,  // notifica di messaggio "file disponibile"
    HANDSHAKE_PH3   = 23,
    HANDSHAKE_ERR   = 24,

    OP_FAIL         = 25,  // generico messaggio di fallimento
    OP_NICK_ALREADY = 26,  // nickname o groupname gia' registrato
    OP_NICK_UNKNOWN = 27,  // nickname non riconosciuto
    OP_MSG_TOOLONG  = 28,  // messaggio con size troppo lunga
    OP_NO_SUCH_FILE = 29,  // il file richiesto non esiste
} command_t;

/**
 * @brief Socket management functions
 */

int readn(long fd, void *buf, size_t size);
int writen(long fd, void *buf, size_t size);
int read_message(int fd, unsigned char* key, unsigned char** message);
int send_message(int fd, unsigned char* key, unsigned char* message);

int serialize_certificate(int fd, X509* srv_cert, unsigned char** cert_buf);
int serialize_pubkey(int fd, EVP_PKEY* pubkey, unsigned char** pubkey_buf);
X509* deserialize_certificate(unsigned char* srv_cert_buf, int srv_cert_len);
EVP_PKEY* deserialize_pubkey(unsigned char* srv_pubkey_buf, int srv_pubkey_len);



#endif /* _UTILS_H_ */