#include "utils.h"
#include "crypto.h"
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
        if (r == 0) return 0; 
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
        cerr << "Fail to write message len" << endl;
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
        cerr << "Fail to read message len" << endl;
        return 0;
    }
    NEW(*message, new unsigned char[*len], "new message");
    err = readn(fd, *message, *len);
    if(err <= 0){
        cerr << "Fail to read message" << endl;
        delete [] *message;
        return 0;
    }
    return 1;
}


int send_udata(int fd, unsigned char* message, uint32_t len){
    int err;
    err = writen(fd, &len, sizeof(uint32_t));
    if(err <= 0){
        cerr << "Fail to write message len" << endl;
        return 0;
    }
    err = writen(fd, message, len);
    if(err <= 0){
        cerr << "Fail to write message" << endl;
        return 0;
    }

    return 1;
}

int read_udata(int fd, unsigned char** message, uint32_t* len){
    int err;
    err = readn(fd, len, sizeof(uint32_t));
    if(err <= 0){
        cerr << "Fail to read message len" << endl;
        return 0;
    }
    NEW(*message, new unsigned char[*len], "new message");
    err = readn(fd, *message, *len);
    if(err <= 0){
        cerr << "Fail to read message" << endl;
        delete [] *message;
        return 0;
    }
    return 1;
}

int send_authenticated_msg(int fd, unsigned char* key, command_t msg_type, uint32_t* seq_number){
    unsigned char* iv;  NEW(iv, new unsigned char[IV_SIZE], "new iv");
    generate_random(iv, IV_SIZE);

    int tag_len, err;

    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), seq_number, sizeof(uint32_t));
    memcpy(aads + sizeof(command_t) + sizeof(uint32_t), iv, IV_SIZE);

    err = gcm_authenticate(aads, AAD_FRAGMNENT, key, iv, tag_buf);
    if (err == 0){
        // Error while encrypting
        cout << "Authenticate message fail" << endl;
        delete [] tag_buf;
        delete [] aads;
        delete [] iv;
        return 0;
    }

    unsigned char* request; NEW(request, new unsigned char[CPHR_FRAGMENT], "new request");
    memcpy(request, &msg_type, sizeof(command_t));
    memcpy(request + sizeof(command_t), seq_number, sizeof(uint32_t));
    memcpy(request + sizeof(command_t) + sizeof(uint32_t), iv, IV_SIZE);
    memcpy(request + sizeof(command_t) + sizeof(uint32_t) + IV_SIZE, tag_buf, TAG_SIZE);

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

command_t read_authenticated_msg(int fd, unsigned char* key, uint32_t* seq_number){
    int err;
    unsigned char* request; NEW(request, new unsigned char[CPHR_FRAGMENT], "new request");
    err = readn(fd, request, CPHR_FRAGMENT);
    if (err <= 0){
        cout << "Fail to read request" << endl;
        delete [] request;
        return OP_FAIL;
    }

    command_t msg_type;
    uint32_t received_seq_number;
    memcpy(&msg_type, request, sizeof(command_t));
    memcpy(&received_seq_number, request + sizeof(command_t), sizeof(uint32_t));
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
    memcpy(aads + sizeof(command_t), &received_seq_number, sizeof(uint32_t));
    memcpy(aads + sizeof(command_t) + sizeof(uint32_t), iv, IV_SIZE);
    memcpy(tag_buf, request + sizeof(command_t) + sizeof(uint32_t) + IV_SIZE, TAG_SIZE);
    delete [] request;
    
    err = gcm_verify(aads, AAD_FRAGMNENT, key, iv, tag_buf);
    
    delete [] tag_buf;
    delete [] iv;
    delete [] aads;
    if (err == 0){
        // error in decrpytion
        cout << "Verify message fail" << endl;
        return OP_FAIL;
    }
    *seq_number = *seq_number + 1;
    return msg_type;
}

int send_message(int fd, unsigned char* key, command_t msg_type, string message, uint32_t* seq_number){

    unsigned char* iv;  NEW(iv, new unsigned char[IV_SIZE], "new iv");
    generate_random(iv, IV_SIZE);

    int plain_len = message.size();

    if(plain_len > INT_MAX - 16){
        cout << "Encrypt send message fail: overflow" << endl;
        delete [] iv;
        return 0;
    } 

    int cphr_len = plain_len + 16;
    int tag_len, err;

    unsigned char* cphr_buf; NEW(cphr_buf, new unsigned char[cphr_len], "new cphr buf");
    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), seq_number, sizeof(uint32_t));
    memcpy(aads + sizeof(command_t) + sizeof(uint32_t), iv, IV_SIZE);

    cphr_len = gcm_encrpyt((unsigned char*)message.c_str(), plain_len, aads, AAD_FRAGMNENT, key, iv, IV_SIZE, cphr_buf, tag_buf);
    if (cphr_len < 0){
        // Error while encrypting
        cout << "Encrypt message fail" << endl;
        delete [] cphr_buf;
        delete [] tag_buf;
        delete [] aads;
        delete [] iv;
        return 0;
    }

    if (cphr_len > INT_MAX - (sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE + TAG_SIZE)){
        // Error while encrypting
        cout << "Send encrypted send message failed: overflow" << endl;
        delete [] cphr_buf;
        delete [] tag_buf;
        delete [] aads;
        delete [] iv;
        return 0;
    }

    int request_len = sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE + cphr_len + TAG_SIZE; 
    unsigned char* request; NEW(request, new unsigned char[request_len], "new request");
    memcpy(request, &msg_type, sizeof(command_t));
    memcpy(request + sizeof(command_t), seq_number, sizeof(uint32_t));
    memcpy(request + sizeof(command_t) + sizeof(uint32_t), &cphr_len, sizeof(int));
    memcpy(request + sizeof(command_t) + sizeof(uint32_t) + sizeof(int), iv, IV_SIZE);
    memcpy(request + sizeof(command_t) + sizeof(uint32_t) + sizeof(int) + IV_SIZE, cphr_buf, cphr_len);
    memcpy(request + sizeof(command_t) + sizeof(uint32_t) + sizeof(int) + IV_SIZE + cphr_len, tag_buf, TAG_SIZE);
    
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

command_t read_message(int fd, unsigned char* key, string &plaintext, uint32_t *seq_number){
    int err, request_len;
    unsigned char* request;

    err = read_data(fd, &request, &request_len);
    if(err == 0){
        cout << "Fail to read request" << endl;
        return OP_FAIL;
    }

    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* iv; NEW(iv, new unsigned char[IV_SIZE], "new iv");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");

    int cphr_len;
    uint32_t received_seq_number;
    command_t msg_type;

    memcpy(&msg_type, request, sizeof(command_t));
    memcpy(&received_seq_number, request + sizeof(command_t), sizeof(uint32_t));
    memcpy(&cphr_len, request + sizeof(command_t) + sizeof(uint32_t), sizeof(int));
    unsigned char* cphr_buf; NEW(cphr_buf, new unsigned char[cphr_len], "new cphr buf");
    memcpy(iv, request + sizeof(command_t) + sizeof(uint32_t) + sizeof(int), IV_SIZE);
    memcpy(cphr_buf, request + sizeof(command_t) + sizeof(uint32_t) + sizeof(int) + IV_SIZE, cphr_len);
    memcpy(tag_buf, request + sizeof(command_t) + sizeof(uint32_t) + sizeof(int) + IV_SIZE + cphr_len, TAG_SIZE);

    if(*seq_number != received_seq_number){
        // message reply detected
        cout << "Different sequence number detected" << endl;
        delete [] request;
        return OP_FAIL;
    }
    
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), seq_number, sizeof(uint32_t));
    memcpy(aads + sizeof(command_t) + sizeof(uint32_t), iv, IV_SIZE);

    delete [] request;
    
    unsigned char* message; NEW(message, new unsigned char[cphr_len], "new message");
    int pt_len = gcm_decrypt(cphr_buf, cphr_len, aads, AAD_FRAGMNENT, tag_buf, key, iv, IV_SIZE, message);
    
    delete [] cphr_buf;
    delete [] tag_buf;
    delete [] iv;
    delete [] aads;
    if (pt_len < 0){
        // error in decrpytion
        cout << "Decrypt message fail" << endl;
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

int send_data_message(int fd, unsigned char* key, command_t msg_type, unsigned char* plaintext, uint32_t pt_len, uint32_t* seq_number){
    unsigned char* iv;  NEW(iv, new unsigned char[IV_SIZE], "new iv");
    generate_random(iv, IV_SIZE);

    if(pt_len > INT_MAX - 16){
        cout << "Encrypt message fail: overflow" << endl;
        delete [] iv;
        return 0;
    } 

    int cphr_len = pt_len + 16;
    int err;

    unsigned char* cphr_buf; NEW(cphr_buf, new unsigned char[cphr_len], "new cphr buf");
    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), seq_number, sizeof(uint32_t));
    memcpy(aads + sizeof(command_t) + sizeof(uint32_t), iv, IV_SIZE);

    cphr_len = gcm_encrpyt(plaintext, pt_len, aads, AAD_FRAGMNENT, key, iv, IV_SIZE, cphr_buf, tag_buf);
    if (cphr_len < 0){
        // Error while encrypting
        cout << "Encrypt message fail" << endl;
        delete [] cphr_buf;
        delete [] tag_buf;
        delete [] aads;
        delete [] iv;
        return 0;
    }

    if (cphr_len > INT_MAX - (sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE + TAG_SIZE)){
        // Error while encrypting
        cout << "Send encrypted message failed: overflow" << endl;
        delete [] cphr_buf;
        delete [] tag_buf;
        delete [] aads;
        delete [] iv;
        return 0;
    }

    int request_len = sizeof(command_t) + sizeof(int) + sizeof(int) + IV_SIZE + cphr_len + TAG_SIZE; 
    unsigned char* request; NEW(request, new unsigned char[request_len], "new request");
    memcpy(request, &msg_type, sizeof(command_t));
    memcpy(request + sizeof(command_t), seq_number, sizeof(uint32_t));
    memcpy(request + sizeof(command_t) + sizeof(uint32_t), &cphr_len, sizeof(int));
    memcpy(request + sizeof(command_t) + sizeof(uint32_t) + sizeof(int), iv, IV_SIZE);
    memcpy(request + sizeof(command_t) + sizeof(uint32_t) + sizeof(int) + IV_SIZE, cphr_buf, cphr_len);
    memcpy(request + sizeof(command_t) + sizeof(uint32_t) + sizeof(int) + IV_SIZE + cphr_len, tag_buf, TAG_SIZE);
    
    // send request with its size
    err = send_data(fd, request, request_len);

    delete [] cphr_buf;
    delete [] tag_buf;
    delete [] request;
    delete [] iv;
    delete [] aads;
    if (err == 0) return err;
    *seq_number = *seq_number + 1;
    return err;
}

command_t read_data_message(int fd, unsigned char* key, unsigned char** plaintext, uint32_t* pt_len, uint32_t *seq_number){
    int err, request_len, decrypt_result;
    unsigned char* request;

    err = read_data(fd, &request, &request_len);
    if(err == 0){
        cout << "Fail to read request" << endl;
        return OP_FAIL;
    }

    unsigned char* tag_buf; NEW(tag_buf, new unsigned char[TAG_SIZE], "new tag buf");
    unsigned char* iv; NEW(iv, new unsigned char[IV_SIZE], "new iv");
    unsigned char* aads; NEW(aads, new unsigned char[AAD_FRAGMNENT], "new aads");

    int cphr_len;
    uint32_t received_seq_number;
    command_t msg_type;

    memcpy(&msg_type, request, sizeof(command_t));
    memcpy(&received_seq_number, request + sizeof(command_t), sizeof(uint32_t));
    memcpy(&cphr_len, request + sizeof(command_t) + sizeof(uint32_t), sizeof(int));
    unsigned char* cphr_buf; NEW(cphr_buf, new unsigned char[cphr_len], "new cphr buf");
    memcpy(iv, request + sizeof(command_t) + sizeof(uint32_t) + sizeof(int), IV_SIZE);
    memcpy(cphr_buf, request + sizeof(command_t) + sizeof(uint32_t) + sizeof(int) + IV_SIZE, cphr_len);
    memcpy(tag_buf, request + sizeof(command_t) + sizeof(uint32_t) + sizeof(int) + IV_SIZE + cphr_len, TAG_SIZE);

    if(*seq_number != received_seq_number){
        // message reply detected
        cout << "Different sequence number detected" << endl;
        delete [] cphr_buf;
        delete [] tag_buf;
        delete [] iv;
        delete [] aads;
        delete [] request;
        return OP_FAIL;
    }
    
    memset(aads, 0, AAD_FRAGMNENT);
    memcpy(aads, &msg_type, sizeof(command_t));
    memcpy(aads + sizeof(command_t), seq_number, sizeof(uint32_t));
    memcpy(aads + sizeof(command_t) + sizeof(uint32_t), iv, IV_SIZE);

    delete [] request;
    
    NEW(*plaintext, new unsigned char[cphr_len], "new message");
    decrypt_result = gcm_decrypt(cphr_buf, cphr_len, aads, AAD_FRAGMNENT, tag_buf, key, iv, IV_SIZE, *plaintext);

    delete [] cphr_buf;
    delete [] tag_buf;
    delete [] iv;
    delete [] aads;
    if (decrypt_result < 0){
        // error in decrpytion
        cout << "Decrypt message fail" << endl;
        delete [] *plaintext;
        return OP_FAIL;
    }
    *pt_len = decrypt_result;
    *seq_number = *seq_number + 1;
    return msg_type;
}

/**
* @brief Serialize a X509 into an unsigned char
*/
uint32_t serialize_certificate(int fd, X509* srv_cert, unsigned char** cert_buf){
    BIO* bio = BIO_new(BIO_s_mem());
    if(!bio){ cerr << "ERROR: Allocating bio" << endl; return 0; }
    if (1 != PEM_write_bio_X509(bio, srv_cert)) { 
        cerr << "ERROR: PEM_write_bio_X509" << endl;
        BIO_free(bio);
        return 0;
    }
    uint32_t cert_buf_len = BIO_ctrl_pending(bio);
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
* @brief Serialize a EVP_PKEY into an unsigned char
*/
uint32_t serialize_pubkey(int fd, EVP_PKEY* pubkey, unsigned char** pubkey_buf){
    BIO* bio = BIO_new(BIO_s_mem());
    if(!bio){ cerr << "ERROR: Allocating bio" << endl; return 0; }
    if (1 != PEM_write_bio_PUBKEY(bio, pubkey)) { 
        cerr << "ERROR: PEM_write_bio_PUBKEY" << endl;
        BIO_free(bio);
        return 0;
    }
    uint32_t pubkey_len = BIO_ctrl_pending(bio);
    NEW(*pubkey_buf, new unsigned char[pubkey_len], "pubkey serialization");
    if(BIO_read(bio, *pubkey_buf, pubkey_len)<=0) { 
        cerr << "ERROR: BIO_read" << endl;
        delete [] *pubkey_buf; *pubkey_buf = NULL;
        pubkey_len = 0;
    }
    BIO_free(bio);
    return pubkey_len;
}

X509* deserialize_certificate(unsigned char* srv_cert_buf, uint32_t srv_cert_len){
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

EVP_PKEY* deserialize_pubkey(unsigned char* srv_pubkey_buf, uint32_t srv_pubkey_len){
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

/* UTILITIES */

bool check_string(string s1){
    if(s1.empty()) return false;
    static char ok_chars[] = "abcdefghijklmnopqrstuvwxyz"
                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "1234567890_.";
    if( s1.find_first_not_of(ok_chars) != string::npos) return false;
    if( (s1.length()>=1 && s1[0] == '.') || (s1.length()==2 && s1[0] == '.' && s1[1]=='.') || (s1.length()==1 && s1[0]=='_')) return false;
    return true;
}

bool strictly_check_string(string s1){
    if(s1.empty()) return false;
    static char ok_chars[] = "abcdefghijklmnopqrstuvwxyz";
    if(s1.find_first_not_of(ok_chars) != string::npos) return false;
    return true;
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
        case FILE_ALREADY:{
            cout << msg <<": new filename already exist in storage." << endl;
            break;
        }
        default:{
            cout << msg << endl;
        }
    }
}

bool unsigned_math(string op, uint32_t a, uint32_t b, uint32_t* result){
    map<string,int> commands;
    commands.insert(pair<string,int>("sum",1));
    commands.insert(pair<string,int>("sub", 2));
    commands.insert(pair<string,int>("div",3));
    commands.insert(pair<string,int>("mul",4));
    commands.insert(pair<string,int>("increment",5));
    commands.insert(pair<string,int>("decrement",6));
    commands.insert(pair<string,int>("module",7));
    switch(commands[op]){
        case 1:{
            // sum
            if(a > UINT32_MAX - b) return false;
            *result = a + b;
            return true;
        }
        case 2:{
            // subtraction
            if (a < b) return false;
            *result = a - b;
            return true;
        }
        case 3:{
            // division
            if (b==0) return false;
            *result = a/b;
            return true;
        }
        case 4:{
            // mul
            if(b!= 0 && a > UINT32_MAX/b) return false;
            *result = a*b;
            return true;
        }
        case 5:{
            // increment
            if(a == UINT32_MAX) return false;
            *result = a++;
            return true;
        }
        case 6:{
            // decrement
            if(a == 0) return false;
            *result = a--;
            return true;
        }
        case 7:{
            //module
            if(b==0) return false;
            *result = a%b;
            return true;
        }
        default:{
            return false;
        }
    }
}