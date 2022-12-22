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

int send_data(int fd, unsigned char* message, int len){
    int err;
    err = writen(fd, &len, sizeof(int));
    if(err <= 0){
        cerr << "Fail to write message" << endl;
        return 0;
    }
    err = writen(fd, message, len);
    if(err <= 0){
        cerr << "Fail to write message" << endl;
        return 0;
    }

    return 1;
}

int read_data(int fd, unsigned char** message, int* len){
    int err;
    err = readn(fd, len, sizeof(int));
    if(err <= 0){
        cerr << "Fail to read message" << endl;
        return 0;
    }
    NEW(*message, new unsigned char[*len], "new message");
    err = readn(fd, *message, *len);
    if(err <= 0){
        cerr << "Fail to read message" << endl;
        return 0;
    }
    return 1;
}

// Deprecated
int my_send_message(int fd, unsigned char* key, command_t msg_type,
    string message, int* seq_number, int nmessages){
    
    unsigned char* message_to_send; 
    NEW(message_to_send, new unsigned char[CLR_FRAGMENT], "message to send");
    memset(message_to_send, 0, CLR_FRAGMENT);
    if(!message.empty()){
        // convert string into a standard size buffer
        memcpy(message_to_send, message.c_str(), message.size());
    }
    
    unsigned char* iv;  NEW(iv, new unsigned char[IV_SIZE], "new iv");
    generate_random(iv, IV_SIZE);

    int cphr_len, tag_len, err;

    unsigned char* cphr_buf; NEW(cphr_buf, new unsigned char[CPHR_FRAGMENT], "new cphr buf");
    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), seq_number, sizeof(int));
    memcpy(aads + sizeof(command_t) + sizeof(int), &nmessages, sizeof(int));
    memcpy(aads + sizeof(command_t) + sizeof(int) + sizeof(int), iv, IV_SIZE);

    cphr_len = gcm_encrpyt(message_to_send, CLR_FRAGMENT, aads, AAD_FRAGMNENT, key, iv, IV_SIZE, cphr_buf, tag_buf);
    if (cphr_len == 0){
        // Error while encrypting
        cout << "Encrypt message fail (occhio alla lunghezza 0)" << endl;
        delete [] cphr_buf;
        delete [] tag_buf;
        delete [] aads;
        delete [] iv;
        delete [] message_to_send;
        return 0;
    }

    unsigned char* request; NEW(request, new unsigned char[MSG_FRAGMENT], "new request");
    memcpy(request, &msg_type, sizeof(command_t));
    memcpy(request + sizeof(command_t), seq_number, sizeof(int));
    memcpy(request + sizeof(command_t) + sizeof(int), &nmessages, sizeof(int));
    memcpy(request + sizeof(command_t) + sizeof(int) + sizeof(int), iv, IV_SIZE);
    memcpy(request + sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE, cphr_buf, CPHR_FRAGMENT);
    memcpy(request + sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE + CPHR_FRAGMENT, tag_buf, TAG_SIZE);

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
    delete [] message_to_send;
    if(err <= 0) return 0;
    *seq_number = *seq_number + 1;
    return cphr_len;

}

// Deprecated
command_t my_read_message(int fd, unsigned char* key, unsigned char** message,
 int* seq_number, int* nmessages){
    int err;
    unsigned char* request; NEW(request, new unsigned char[MSG_FRAGMENT], "new request");
    err = readn(fd, request, MSG_FRAGMENT);
    if (err <= 0){
        cout << "Fail to read request" << endl;
        delete [] request;
        return OP_FAIL;
    }

    command_t msg_type;
    int received_seq_number;
    memcpy(&msg_type, request, sizeof(command_t));
    memcpy(&received_seq_number, request + sizeof(command_t), sizeof(int));
    memcpy(nmessages, request + sizeof(command_t) + sizeof(int), sizeof(int));

    if(*seq_number != received_seq_number){
        // message reply detected
        cout << "Different sequence number detected" << endl;
        delete [] request;
        return OP_FAIL;
    }

    unsigned char* cphr_buf; NEW(cphr_buf, new unsigned char[CPHR_FRAGMENT], "new cphr buf");
    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* iv; NEW(iv, new unsigned char[IV_SIZE], "new iv");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");

    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(iv, request + sizeof(command_t) + sizeof(int) + sizeof(int), IV_SIZE);

    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), &received_seq_number, sizeof(int));
    memcpy(aads + sizeof(command_t) + sizeof(int), nmessages, sizeof(int));
    memcpy(aads + sizeof(command_t) + sizeof(int) + sizeof(int), iv, IV_SIZE);
    //cout << "Received sequence number " << received_seq_number << endl;
    //cout << "Received message type " << msg_type << endl;

    memcpy(cphr_buf, request + sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE, CPHR_FRAGMENT);
    memcpy(tag_buf, request + sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE + CPHR_FRAGMENT, TAG_SIZE);

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
        return OP_FAIL;
    }
    *seq_number = *seq_number + 1;
    return msg_type;
}

int send_authenticated_msg(int fd, unsigned char* key, command_t msg_type, int* seq_number){
    unsigned char* iv;  NEW(iv, new unsigned char[IV_SIZE], "new iv");
    generate_random(iv, IV_SIZE);

    int tag_len, err;

    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), seq_number, sizeof(int));
    memcpy(aads + sizeof(command_t) + sizeof(int), iv, IV_SIZE);

    err = gcm_authenticate(aads, AAD_FRAGMNENT, key, iv, tag_buf);
    if (err == 0){
        // Error while encrypting
        cout << "Authenticate message fail (occhio alla lunghezza 0)" << endl;
        delete [] tag_buf;
        delete [] aads;
        delete [] iv;
        return 0;
    }

    unsigned char* request; NEW(request, new unsigned char[CPHR_FRAGMENT], "new request");
    memcpy(request, &msg_type, sizeof(command_t));
    memcpy(request + sizeof(command_t), seq_number, sizeof(int));
    memcpy(request + sizeof(command_t) + sizeof(int), iv, IV_SIZE);
    memcpy(request + sizeof(command_t) + sizeof(int) + IV_SIZE, tag_buf, TAG_SIZE);

    // Send to server the message
    err = writen(fd, request, CPHR_FRAGMENT);
    
    delete [] tag_buf;
    delete [] request;
    delete [] iv;
    delete [] aads;
    if(err <= 0) return 0;
    *seq_number = *seq_number + 1;
    return 1;
}

command_t read_authenticated_msg(int fd, unsigned char* key, int* seq_number){
    int err;
    unsigned char* request; NEW(request, new unsigned char[CPHR_FRAGMENT], "new request");
    err = readn(fd, request, CPHR_FRAGMENT);
    if (err <= 0){
        cout << "Fail to read request" << endl;
        delete [] request;
        return OP_FAIL;
    }

    command_t msg_type;
    int received_seq_number;
    memcpy(&msg_type, request, sizeof(command_t));
    memcpy(&received_seq_number, request + sizeof(command_t), sizeof(int));
    if(*seq_number != received_seq_number){
        // message reply detected
        cout << "Different sequence number detected" << endl;
        delete [] request;
        return OP_FAIL;
    }

    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* iv; NEW(iv, new unsigned char[IV_SIZE], "new iv");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");

    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(iv, request + sizeof(command_t) + sizeof(int), IV_SIZE);

    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), &received_seq_number, sizeof(int));
    memcpy(aads + sizeof(command_t) + sizeof(int), iv, IV_SIZE);
    //cout << "Received sequence number " << received_seq_number << endl;
    //cout << "Received message type " << msg_type << endl;
    memcpy(tag_buf, request + sizeof(command_t) + sizeof(int) + IV_SIZE, TAG_SIZE);
    delete [] request;
    
    err = gcm_verify(aads, AAD_FRAGMNENT, key, iv, tag_buf);
    
    delete [] tag_buf;
    delete [] iv;
    delete [] aads;
    if (err == 0){
        // error in decrpytion
        cout << "Verify message fail (occhio alla lunghezza 0)" << endl;
        return OP_FAIL;
    }
    *seq_number = *seq_number + 1;
    return msg_type;
}

int send_message(int fd, unsigned char* key, command_t msg_type, string message, int* seq_number){

    unsigned char* iv;  NEW(iv, new unsigned char[IV_SIZE], "new iv");
    generate_random(iv, IV_SIZE);

    int plain_len = message.size();
    int cphr_len = plain_len + 16;
    int tag_len, err;

    unsigned char* cphr_buf; NEW(cphr_buf, new unsigned char[cphr_len], "new cphr buf");
    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), seq_number, sizeof(int));
    memcpy(aads + sizeof(command_t) + sizeof(int), iv, IV_SIZE);

    cphr_len = gcm_encrpyt((unsigned char*)message.c_str(), plain_len, aads, AAD_FRAGMNENT, key, iv, IV_SIZE, cphr_buf, tag_buf);
    if (cphr_len < 0){
        // Error while encrypting
        cout << "Encrypt message fail (occhio alla lunghezza 0)" << endl;
        delete [] cphr_buf;
        delete [] tag_buf;
        delete [] aads;
        delete [] iv;
        return 0;
    }

    int request_len = sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE + cphr_len + TAG_SIZE; 
    unsigned char* request; NEW(request, new unsigned char[request_len], "new request");
    memcpy(request, &msg_type, sizeof(command_t));
    memcpy(request + sizeof(command_t), seq_number, sizeof(int));
    memcpy(request + sizeof(command_t) + sizeof(int), &cphr_len, sizeof(int));
    memcpy(request + sizeof(command_t) + sizeof(int) + sizeof(int), iv, IV_SIZE);
    memcpy(request + sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE, cphr_buf, cphr_len);
    memcpy(request + sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE + cphr_len, tag_buf, TAG_SIZE);
    
    // send request with its size
    err = send_data(fd, request, request_len);

    delete [] cphr_buf;
    delete [] tag_buf;
    delete [] request;
    delete [] iv;
    delete [] aads;
    if(err == 0) return 0;
    *seq_number = *seq_number + 1;
    return 1;
}

command_t read_message(int fd, unsigned char* key, string &plaintext, int *seq_number){
    int err, request_len;
    unsigned char* request;

    err = read_data(fd, &request, &request_len);
    if(err == 0){
        cout << "Fail to read request" << endl;
        delete [] request;
        return OP_FAIL;
    }

    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* iv; NEW(iv, new unsigned char[IV_SIZE], "new iv");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");

    int cphr_len, received_seq_number;
    command_t msg_type;

    memcpy(&msg_type, request, sizeof(command_t));
    memcpy(&received_seq_number, request + sizeof(command_t), sizeof(int));
    memcpy(&cphr_len, request + sizeof(command_t) + sizeof(int), sizeof(int));
    unsigned char* cphr_buf; NEW(cphr_buf, new unsigned char[cphr_len], "new cphr buf");
    memcpy(iv, request + sizeof(command_t) + sizeof(int) + sizeof(int), IV_SIZE);
    memcpy(cphr_buf, request + sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE, cphr_len);
    memcpy(tag_buf, request + sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE + cphr_len, TAG_SIZE);

    if(*seq_number != received_seq_number){
        // message reply detected
        cout << "Different sequence number detected" << endl;
        delete [] request;
        return OP_FAIL;
    }
    
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), seq_number, sizeof(int));
    memcpy(aads + sizeof(command_t) + sizeof(int), iv, IV_SIZE);

    delete [] request;
    
    unsigned char* message; NEW(message, new unsigned char[cphr_len], "new message");
    int pt_len = gcm_decrypt(cphr_buf, cphr_len, aads, AAD_FRAGMNENT, tag_buf, key, iv, IV_SIZE, message);
    
    delete [] cphr_buf;
    delete [] tag_buf;
    delete [] iv;
    delete [] aads;
    if (pt_len < 0){
        // error in decrpytion
        cout << "Decrypt message fail (occhio alla lunghezza 0)" << endl;
        delete [] message;
        return OP_FAIL;
    }

    char* chr_message; NEW(chr_message, new char[pt_len + 1],"new chr_message");
    memmove(chr_message,message,pt_len);
    chr_message[pt_len] = '\0';
    plaintext = (string) chr_message;
    delete [] message;
    delete [] chr_message;
    *seq_number = *seq_number + 1;
    return msg_type;
}

int send_data_message(int fd, unsigned char* key, command_t msg_type, unsigned char* plaintext, int pt_len, int* seq_number){
    unsigned char* iv;  NEW(iv, new unsigned char[IV_SIZE], "new iv");
    generate_random(iv, IV_SIZE);

    int cphr_len = pt_len + 16;
    int tag_len, err;

    unsigned char* cphr_buf; NEW(cphr_buf, new unsigned char[cphr_len], "new cphr buf");
    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), seq_number, sizeof(int));
    memcpy(aads + sizeof(command_t) + sizeof(int), iv, IV_SIZE);

    cphr_len = gcm_encrpyt(plaintext, pt_len, aads, AAD_FRAGMNENT, key, iv, IV_SIZE, cphr_buf, tag_buf);
    if (cphr_len < 0){
        // Error while encrypting
        cout << "Encrypt message fail (occhio alla lunghezza 0)" << endl;
        delete [] cphr_buf;
        delete [] tag_buf;
        delete [] aads;
        delete [] iv;
        return 0;
    }

    int request_len = sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE + cphr_len + TAG_SIZE; 
    unsigned char* request; NEW(request, new unsigned char[request_len], "new request");
    memcpy(request, &msg_type, sizeof(command_t));
    memcpy(request + sizeof(command_t), seq_number, sizeof(int));
    memcpy(request + sizeof(command_t) + sizeof(int), &cphr_len, sizeof(int));
    memcpy(request + sizeof(command_t) + sizeof(int) + sizeof(int), iv, IV_SIZE);
    memcpy(request + sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE, cphr_buf, cphr_len);
    memcpy(request + sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE + cphr_len, tag_buf, TAG_SIZE);
    
    // send request with its size
    err = send_data(fd, request, request_len);

    delete [] cphr_buf;
    delete [] tag_buf;
    delete [] request;
    delete [] iv;
    delete [] aads;
    
    *seq_number = *seq_number + 1;
    return err;
}

command_t read_data_message(int fd, unsigned char* key, unsigned char** plaintext, int* pt_len, int *seq_number){
    int err, request_len;
    unsigned char* request;

    err = read_data(fd, &request, &request_len);
    if(err == 0){
        cout << "Fail to read request" << endl;
        delete [] request;
        return OP_FAIL;
    }

    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* iv; NEW(iv, new unsigned char[IV_SIZE], "new iv");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");

    int cphr_len, received_seq_number;
    command_t msg_type;

    memcpy(&msg_type, request, sizeof(command_t));
    memcpy(&received_seq_number, request + sizeof(command_t), sizeof(int));
    memcpy(&cphr_len, request + sizeof(command_t) + sizeof(int), sizeof(int));
    unsigned char* cphr_buf; NEW(cphr_buf, new unsigned char[cphr_len], "new cphr buf");
    memcpy(iv, request + sizeof(command_t) + sizeof(int) + sizeof(int), IV_SIZE);
    memcpy(cphr_buf, request + sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE, cphr_len);
    memcpy(tag_buf, request + sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE + cphr_len, TAG_SIZE);

    if(*seq_number != received_seq_number){
        // message reply detected
        cout << "Different sequence number detected" << endl;
        delete [] request;
        return OP_FAIL;
    }
    
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), seq_number, sizeof(int));
    memcpy(aads + sizeof(command_t) + sizeof(int), iv, IV_SIZE);

    delete [] request;
    
    NEW(*plaintext, new unsigned char[cphr_len], "new message");
    *pt_len = gcm_decrypt(cphr_buf, cphr_len, aads, AAD_FRAGMNENT, tag_buf, key, iv, IV_SIZE, *plaintext);
    
    delete [] cphr_buf;
    delete [] tag_buf;
    delete [] iv;
    delete [] aads;
    if (*pt_len < 0){
        // error in decrpytion
        cout << "Decrypt message fail (occhio alla lunghezza 0)" << endl;
        delete [] *plaintext;
        return OP_FAIL;
    }
    
    *seq_number = *seq_number + 1;
    return msg_type;
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

void error_msg_type(string msg, command_t msg_type){
    switch(msg_type){
        case OP_FAIL:{
            cout << msg << ": operation failed." << endl;
            break;
        }
        case NO_SUCH_FILE:{
            cout << msg << ": no such file." << endl;
            break;
        }
        case NOT_VALID_FILE:{
            cout << msg << ": file too big or empty." << endl;
            break;
        }
        default:{
            cout << msg << endl;
        }
    }
}