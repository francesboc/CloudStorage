#include <iostream>
#include <stdio.h>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include <fstream>

#define IP "127.0.0.1"
#define PORT 4333

bool list_command(int fd, unsigned char** key, uint32_t* seq_number);
bool delete_command(int fd, unsigned char* key, uint32_t* seq_number);
bool upload_command(int fd, unsigned char* key, uint32_t* seq_number);
bool download_command(int fd, unsigned char* key, uint32_t* seq_number);
bool rename_command(int fd, unsigned char* key, uint32_t* seq_number);

void show_welcome_msg();
void help_msg();

unsigned char* handshake(int fd, string username);
void handshake_error(int fd, string reason_msg);
unsigned char* update_key(int fd, unsigned char* key, uint32_t* seq_number);

string USERNAME;
string STORAGE_PATH;
string USER_PATH;
string CA_CERT_PATH;
string CA_CRL_PATH;


int main(){
    show_welcome_msg();

    cout << "Enter your username: ";
    getline(cin, USERNAME);
    if(!cin) { cerr << "Error during input\n"; exit(1); }
    if(!check_string(USERNAME)){
        cout << "Username not valid. Please retry." << endl;
        return 0;
    }
    if(USERNAME.size() > USRNM_LEN) USERNAME.resize(USRNM_LEN);
    
    int client_skt;
    struct sockaddr_in address;

    memset(&address,0,sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, IP, &address.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    if((client_skt = socket(AF_INET, SOCK_STREAM, 0))<0){
        perror("Error during socket");
        exit(EXIT_FAILURE);
    }  

    cout << "Trying to connect" << endl;

    while(connect(client_skt,(struct sockaddr*) &address, sizeof(address))==-1){
        if( errno == ENOENT) sleep(1);
        else{
            perror("Error");
            exit(EXIT_FAILURE);
        } 
    }

    // Possible commands
    map<string,int> commands;
    commands.insert(pair<string,int>("list",LIST));
    commands.insert(pair<string,int>("upload", UPLOAD));
    commands.insert(pair<string,int>("download",DOWNLOAD));
    commands.insert(pair<string,int>("rename",RENAME));
    commands.insert(pair<string,int>("delete",DELETE));
    commands.insert(pair<string,int>("logout",LOGOUT));
    commands.insert(pair<string,int>("help",HELP));

    string command;
    char cwd[256]; 
    if(getcwd(cwd, 256) == NULL) exit(EXIT_FAILURE);

    USER_PATH = (string)cwd + (string)"/" + USERNAME;
    STORAGE_PATH = USER_PATH + (string)"/storage/";
    CA_CERT_PATH = USER_PATH + (string)"/FoundationsOfCybersecurity_cert.pem";
    CA_CRL_PATH = USER_PATH + (string)"/FoundationsOfCybersecurity_crl.pem";

    unsigned char* key = handshake(client_skt, USERNAME);
    if (!key) {
        close(client_skt);
        return 0;
    }
    int keylen = EVP_CIPHER_key_length(EVP_aes_128_gcm());
    uint32_t seq_number = 0;

    cout << "Handshake successful. Established secure communication ✅\n" << endl;

    int logged_in = 1;
    while(logged_in){
        // Check if a key update is needed (to avoid seq number wrap around)
        if(seq_number >= (UINT32_MAX - UPDATE_KEY_LIMIT)){  
            // Update session key
            cout << "Key needs to be changed" << endl;
            key = update_key(client_skt, key, &seq_number);
            if(!key){
                cout << "Update key failed" << endl;
                close(client_skt);
                free_crypto(key,keylen);
                return 0;
            }
        }
        cout << "Enter command: ";
        getline(cin, command);
        if(!cin) { cerr << "Error during input\n"; close(client_skt); exit(1); }
        for(int i=0; i<command.length(); i++)
            command[i] = tolower(command[i]);
        if(!strictly_check_string(command)){
            cout << "Command not valid. Type help for a list of allowed commands." << endl;
            continue;
        }

        switch(commands[command]) {
            case LIST:{
                cout << "List command inserted" << endl;
                if(!list_command(client_skt, &key, &seq_number))
                    logged_in = 0;
                break;
            }
            case UPLOAD:{
                cout << "Upload command inserted" << endl;
                if(!upload_command(client_skt, key, &seq_number))
                    logged_in = 0;
                break;
            }
            case DOWNLOAD:{
                cout << "Download command inserted" << endl;
                if(!download_command(client_skt, key, &seq_number))
                    logged_in = 0;
                break;
            }
            case LOGOUT:{
                int err = send_message(client_skt, key, LOGOUT,"", &seq_number);
                if(err==0){
                    cout << "Cannot send logout message, terminating" << endl;
                }
                logged_in = 0;
                break;
            }
            case DELETE:{
                cout << "Delete command inserted" << endl;
                if(!delete_command(client_skt, key, &seq_number))
                    logged_in = 0;
                break;
            }
            case RENAME:{
                cout << "Rename command inserted" << endl;
                if(!rename_command(client_skt, key, &seq_number))
                    logged_in = 0;
                break;
            }
            case HELP:{
                help_msg();
                break;
            }
            default:
                cout << "Command not recognized. Type help for a list of allowed commands." << endl;
                break;
        }
    }
    // FREE CRYPTO MATERIAL
    free_crypto(key, keylen);
    close(client_skt);
    return 0;
}

unsigned char* handshake(int fd, string username){

    int err;
    unsigned int handshake_msg_len;
    unsigned char* srv_nonce = NULL; 
    unsigned char* shared_key = NULL;
    unsigned char* srv_cert_buf = NULL;
    unsigned char* srv_pubkey_buf = NULL;
    unsigned char* handshake_msg = NULL;
    X509* srv_cert = NULL;
    EVP_PKEY* srv_dh_pubkey = NULL;
    EVP_PKEY *my_dhkey = NULL;
    command_t msg_type;

    /* ------------------------------------------------------------------------------------ */
    /* FIRST PHASE: Client sends nonce and username                                         */
    /* ------------------------------------------------------------------------------------ */

    unsigned char* clt_nonce; NEW(clt_nonce, new unsigned char[NONCE_LEN], "client nonce");
    generate_random(clt_nonce, NONCE_LEN);

    cout << "Generating crypto material..." << endl;
    unsigned int username_size = username.size();
    msg_type = HANDSHAKE_PH1;

    if(!unsigned_math("sum", (sizeof(command_t) + NONCE_LEN + sizeof(unsigned int)), username_size, &handshake_msg_len)){
        cout << "Overflow error" << endl;
        delete [] clt_nonce;
        return NULL;
    }

    NEW(handshake_msg, new unsigned char[handshake_msg_len], "phase1: handshake msg");
    memcpy(handshake_msg, &msg_type, sizeof(command_t));
    memcpy(handshake_msg + sizeof(command_t), clt_nonce, NONCE_LEN);
    memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN, &username_size, sizeof(unsigned int));
    memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN + sizeof(unsigned int), username.c_str(), username_size);

    err = send_udata(fd, handshake_msg, handshake_msg_len);
    delete [] handshake_msg;
    if(err == 0){
        delete [] clt_nonce;
        return NULL;
    }
    
    bool handshake_finished = false;
    bool error_occurred = false;
    
    while(!handshake_finished && !error_occurred){
        err = read_udata(fd, &handshake_msg, &handshake_msg_len);
        if(err == 0) { error_occurred = true; break; }
        
        // Get message type
        memcpy(&msg_type, handshake_msg, sizeof(command_t));

        switch(msg_type) {
            case HANDSHAKE_PH2:{

                /* ------------------------------------------------------------------------------------ */
                /* SECOND PHASE: server exchange                                                        */
                /* Client receives srv certificate, ephimeral srv pub key, signature                    */
                /* Client retrieve public key from srv certificate, verify the signature                */
                /* ------------------------------------------------------------------------------------ */

                NEW(srv_nonce, new unsigned char[NONCE_LEN], "server nonce");
                memcpy(srv_nonce, handshake_msg + sizeof(command_t), NONCE_LEN);

                unsigned char* received_clt_nonce;
                NEW(received_clt_nonce, new unsigned char[NONCE_LEN], "received clt nonce");

                // Get Client.Nonce for freshness
                memcpy(received_clt_nonce, handshake_msg + sizeof(command_t) + NONCE_LEN, NONCE_LEN);
                
                if(CRYPTO_memcmp(clt_nonce, received_clt_nonce, NONCE_LEN) != 0){
                    cout << "Detect different nonces, abort" << endl;
                    // nonces are different, abort
                    handshake_error(fd, "Nonces are different");
                    error_occurred = true; break;
                }

                // Get server certificate
                unsigned int srv_cert_len, srv_pubkey_len, signature_len;
                memcpy(&srv_cert_len, handshake_msg + sizeof(command_t) + (NONCE_LEN*2), sizeof(unsigned int));
                memcpy(&srv_pubkey_len, handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + sizeof(unsigned int), sizeof(unsigned int));
                memcpy(&signature_len, handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(unsigned int)*2), sizeof(unsigned int));

                NEW(srv_cert_buf, new unsigned char[srv_cert_len], "server certificate");
                memcpy(srv_cert_buf, handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(unsigned int)*3), srv_cert_len);

                NEW(srv_pubkey_buf, new unsigned char[srv_pubkey_len], "server public key");
                memcpy(srv_pubkey_buf, handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(unsigned int)*3) + srv_cert_len, srv_pubkey_len);

                srv_cert = deserialize_certificate(srv_cert_buf, srv_cert_len);
                if(!srv_cert){ 
                    cout << "Errore srv cert" << endl;
                    handshake_error(fd, "Client error");
                    error_occurred = true; break;
                }

                srv_dh_pubkey = deserialize_pubkey(srv_pubkey_buf, srv_pubkey_len);
                if(!srv_dh_pubkey){
                    cout << "Errore dh srv" << endl;
                    handshake_error(fd, "Client error");
                    error_occurred = true; break;
                }

                unsigned char* signature; NEW(signature, new unsigned char[signature_len], "server signature");
                memcpy(signature, handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(unsigned int)*3) + srv_cert_len + srv_pubkey_len, signature_len);
                
                delete [] handshake_msg;
                
                // Load the CA's certificate
                FILE* cacert_file = fopen(CA_CERT_PATH.c_str(), "r");
                if(!cacert_file){ 
                    cerr << "Error: cannot open file '" << CA_CERT_PATH << "' (missing?)\n";
                    handshake_error(fd, "Client error");
                    delete [] signature;
                    error_occurred = true; break;
                }
                X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
                fclose(cacert_file);
                if(!cacert){ 
                    cerr << "Error: PEM_read_X509 returned NULL\n";
                    handshake_error(fd, "Client error");
                    delete [] signature;
                    error_occurred = true; break;
                }
                
                // load the CRL:
                FILE* crl_file = fopen(CA_CRL_PATH.c_str(), "r");
                if(!crl_file){ 
                    cerr << "Error: cannot open file '" << CA_CRL_PATH << "' (missing?)\n";
                    handshake_error(fd, "Client error");
                    delete [] signature;
                    X509_free(cacert);
                    error_occurred = true; break; 
                }

                X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
                fclose(crl_file);
                if(!crl){ 
                    cerr << "Error: PEM_read_X509_CRL returned NULL\n";
                    handshake_error(fd, "Client error");
                    delete [] signature;
                    X509_free(cacert);
                    error_occurred = true; break; 
                }

                int verify_cert = verify_certificate(cacert, crl, srv_cert);
                if(verify_cert == 0){
                    cout << "ERRORE Certificate verification FAILED" << endl;
                    handshake_error(fd, "Certificate not valid");
                    delete [] signature;
                    error_occurred = true;
                    break;
                }
                
                // We need to verify signature
                unsigned int to_verify_len;
                if(!unsigned_math("sum",srv_pubkey_len, (NONCE_LEN*2), &to_verify_len)){
                    cout << "Overflow error" << endl;
                    handshake_error(fd, "Client error");
                    delete [] signature;
                    error_occurred = true; break;
                }

                unsigned char* to_verify; NEW(to_verify, new unsigned char[to_verify_len], "to_verify buffer");
                memcpy(to_verify, srv_pubkey_buf, srv_pubkey_len);
                memcpy(to_verify + srv_pubkey_len, clt_nonce, NONCE_LEN);
                memcpy(to_verify + srv_pubkey_len + NONCE_LEN, srv_nonce, NONCE_LEN);

                // extract pubic key from srv certificate
                EVP_PKEY* srv_cert_pubkey = X509_get_pubkey(srv_cert);
                if(!srv_cert_pubkey){
                    cout << "Errore srv_cert_pubkey" << endl;
                    handshake_error(fd, "Client error");
                    delete [] signature;
                    delete [] to_verify;
                    error_occurred = true; break; 
                }

                int verify = verify_signature(srv_cert_pubkey, to_verify, to_verify_len, signature, signature_len);
                if(verify == 0){
                    handshake_error(fd, "Signature not valid");
                    delete [] signature;
                    delete [] to_verify;
                    EVP_PKEY_free(srv_cert_pubkey);
                    error_occurred = true;
                    break;
                }
                cout << "Checking secret stuffs...\n" << endl;
                delete [] to_verify;
                delete [] signature;
                delete [] srv_cert_buf; srv_cert_buf = NULL;
                delete [] srv_pubkey_buf; srv_pubkey_buf = NULL;
                EVP_PKEY_free(srv_cert_pubkey);

                /* ------------------------------------------------------------------------------------ */
                /* THIRD PHASE: server exchange                                                        */
                /* Client receives srv certificate, ephimeral srv pub key, signature                    */
                /* Client retrieve public key from srv certificate, verify the signature                */
                /* ------------------------------------------------------------------------------------ */

                // Generate ephimeral DH
                my_dhkey = generate_pubkey();
                if(!my_dhkey){
                    cout << "ERRORE mydh key" << endl;
                    handshake_error(fd, "Client error");
                    error_occurred = true; break; 
                }

                unsigned char* pubkey_buf;
                unsigned int pubkey_buf_len = serialize_pubkey(fd, my_dhkey, &pubkey_buf);
                if (pubkey_buf_len == 0){
                    cout << "ERRORE pubkey buf len" << endl;
                    handshake_error(fd, "Client error");
                    error_occurred = true; break; 
                }

                // First read client privkey
                string path = USER_PATH + "/" + username + "_prvkey.pem";
                FILE* prvkey_file = fopen(path.c_str(), "r");
                if(!prvkey_file){ 
                    cout << "Errore prvkey file" << endl;
                    handshake_error(fd, "Client error");
                    delete [] pubkey_buf;
                    error_occurred = true; break; 
                }

                EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
                fclose(prvkey_file);
                if(!prvkey){
                    cout << "Errore file" << endl;
                    handshake_error(fd, "Client error");
                    delete [] pubkey_buf;
                    error_occurred = true; break; 
                }

                unsigned int to_sign_len;
                if(!unsigned_math("sum", pubkey_buf_len, (NONCE_LEN*2), &to_sign_len)){
                    cout << "Overflow error" << endl;
                    handshake_error(fd, "Client error");
                    delete [] pubkey_buf;
                    error_occurred = true; break; 
                }
                unsigned char* to_sign; NEW(to_sign, new unsigned char[to_sign_len], "to sign buffer");
                memcpy(to_sign, pubkey_buf, pubkey_buf_len);
                memcpy(to_sign + pubkey_buf_len, clt_nonce, NONCE_LEN);
                memcpy(to_sign + pubkey_buf_len + NONCE_LEN, srv_nonce, NONCE_LEN);

                NEW(signature, new unsigned char[EVP_PKEY_size(prvkey)], "signature buffer");
                signature_len = sign(prvkey, to_sign, to_sign_len, signature);
                if(signature_len == 0){
                    cout << "ERRORE signature_len" << endl;
                    handshake_error(fd, "Client error");
                    delete [] pubkey_buf;
                    delete [] to_sign;
                    delete [] signature;
                    EVP_PKEY_free(prvkey);
                    error_occurred = true; break; 
                }

                delete [] to_sign;
                EVP_PKEY_free(prvkey);

                msg_type = HANDSHAKE_PH3;
                bool ok_math = true && unsigned_math("sum", (sizeof(command_t) + NONCE_LEN + (sizeof(unsigned int)*2)), pubkey_buf_len, &handshake_msg_len);
                ok_math = ok_math && unsigned_math("sum", handshake_msg_len, signature_len, &handshake_msg_len);
                if(!ok_math){
                    cout << "Overflow error" << endl;
                    handshake_error(fd, "Client error");
                    delete [] pubkey_buf;
                    delete [] signature;
                    EVP_PKEY_free(prvkey);
                    error_occurred = true; break; 
                }

                NEW(handshake_msg, new unsigned char[handshake_msg_len], "phase3: handshake msg");
                memcpy(handshake_msg, &msg_type, sizeof(command_t));
                memcpy(handshake_msg + sizeof(command_t), srv_nonce, NONCE_LEN);
                memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN, &pubkey_buf_len, sizeof(unsigned int));
                memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN + sizeof(unsigned int), &signature_len, sizeof(unsigned int));
                memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN + (sizeof(unsigned int)*2), pubkey_buf, pubkey_buf_len);
                memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN + (sizeof(unsigned int)*2) + pubkey_buf_len, signature, signature_len);

                err = send_udata(fd, handshake_msg, handshake_msg_len);
                if (err == 0){error_occurred = true; break;}

                delete [] handshake_msg;                
                delete [] pubkey_buf;
                delete [] signature;

                // Derive the shared secret
                unsigned char* skey;
                unsigned int skeylen = derive_shared_secret(my_dhkey, srv_dh_pubkey, &skey);
                if (skeylen == 0){
                    cout << "ERRORE skeylen" << endl;
                    handshake_error(fd, "Client error");
                    error_occurred = true; break; 
                }

                // Using SHA-256 to extract a safe key!
                unsigned char* digest; 
                NEW(digest, new unsigned char[EVP_MD_size(EVP_sha256())], "digest for secret key");

                unsigned int digestlen = hash_secret(digest, skey, skeylen);
                if (digestlen == 0){
                    cout << "ERRORE digestlen1" << endl;
                    handshake_error(fd, "Client error");
                    free_crypto(skey, skeylen);
                    error_occurred = true; break; 
                }

                unsigned int keylen = EVP_CIPHER_key_length(EVP_aes_128_gcm());
                NEW(shared_key, new unsigned char[keylen], "shared secret");
                memcpy(shared_key, digest, keylen);

                free_crypto(digest, digestlen);
                free_crypto(skey, skeylen);
                handshake_finished = true;
                break;
            }
            case HANDSHAKE_ERR:{
                cout << "Something went wrong during handshake:" << endl;
                
                unsigned int reason_len;
                memcpy(&reason_len, handshake_msg + sizeof(command_t), sizeof(unsigned int));

                char *reason; NEW(reason, new char[reason_len+1], "reason msg");
                memcpy(reason, handshake_msg + sizeof(command_t)+ sizeof(unsigned int), reason_len);
                
                reason[reason_len] = '\0';
                cout << reason << endl;
                delete [] reason;
                delete [] handshake_msg;
                error_occurred = true; 
                break;
            }
            default:{
                cout << "Command not recognized" << endl;
                error_occurred = true; 
                break;
            }
        }
    }   

    if (error_occurred){
        if(clt_nonce) delete [] clt_nonce;
        if(srv_nonce) delete [] srv_nonce;
        if(srv_cert_buf) delete [] srv_cert_buf;
        if(srv_pubkey_buf) delete [] srv_pubkey_buf;
        if(srv_dh_pubkey) EVP_PKEY_free(srv_dh_pubkey);
        if(my_dhkey) EVP_PKEY_free(my_dhkey);
        if(srv_cert) X509_free(srv_cert);
        return NULL;
    }

    return shared_key;
}

void handshake_error(int fd, string reason_msg){
    // user not registered or already online
    command_t msg_type = HANDSHAKE_ERR;
    int reason_len = reason_msg.size();
    int error_msg_len = sizeof(command_t) + sizeof(unsigned int) + reason_len;
    unsigned char* _error_msg = NULL;
    NEW(_error_msg, new unsigned char[error_msg_len], "error message");
    memcpy(_error_msg, &msg_type, sizeof(command_t));
    memcpy(_error_msg + sizeof(command_t), &reason_len, sizeof(unsigned int));
    memcpy(_error_msg + sizeof(command_t) + sizeof(unsigned int),reason_msg.c_str(), reason_len);
    send_data(fd, _error_msg, error_msg_len);
    delete [] _error_msg;
    return;
}

unsigned char* update_key(int fd, unsigned char* key, uint32_t* seq_number){
    command_t msg_type;
    // Sending request to update key
    int err = send_authenticated_msg(fd, key, UPDATE_KEY_REQ, seq_number);
    if(err == 0){
        cout << "Fail to send update key command" << endl;
        return NULL;
    }
    msg_type = read_authenticated_msg(fd,key, seq_number);
    if(msg_type != UPDATE_KEY_ACK)
        return NULL;

    // Now we can start the new exchange
    unsigned char* update_key_msg = NULL;
    unsigned char* pubkey_buf = NULL;
    unsigned char* srv_pubkey_buf = NULL;
    int srv_pubkey_len;
    EVP_PKEY* srv_dh_pubkey = NULL;
    EVP_PKEY* my_dhkey = NULL;
    
    // Generate ephimeral DH
    my_dhkey = generate_pubkey();
    if(!my_dhkey){
        cout << "ERRORE mydh key" << endl;
        return NULL;
    }

    unsigned int pubkey_buf_len = serialize_pubkey(fd, my_dhkey, &pubkey_buf);
    if (pubkey_buf_len == 0){
        cout << "ERRORE pubkey buf len" << endl;
        return NULL;
    }

    err = send_data_message(fd, key, UPDATE_KEY_REQ, pubkey_buf, pubkey_buf_len, seq_number);
    if (err == 0)
        return NULL;

    msg_type = read_data_message(fd, key, &srv_pubkey_buf, &srv_pubkey_len, seq_number);
    if(msg_type == OP_FAIL) return NULL;

    srv_dh_pubkey = deserialize_pubkey(srv_pubkey_buf, srv_pubkey_len);
    if(!srv_dh_pubkey){
        cout << "Errore dh srv" << endl;
        return NULL;
    }

    delete [] srv_pubkey_buf;
    delete [] pubkey_buf;

    // Derive new shared secret
    unsigned char* skey;
    unsigned int skeylen = derive_shared_secret(my_dhkey, srv_dh_pubkey, &skey);
    if (skeylen == 0){
        cout << "ERRORE skeylen" << endl;
        return NULL;
    }

    // Using SHA-256 to extract a safe key!
    unsigned char* digest; 
    NEW(digest, new unsigned char[EVP_MD_size(EVP_sha256())], "digest for secret key");
    unsigned int digestlen = hash_secret(digest, skey, skeylen);
    if (digestlen == 0){
        cout << "ERRORE digestlen1" << endl;
        free_crypto(skey, skeylen);
        return NULL;
    }

    int keylen = EVP_CIPHER_key_length(EVP_aes_128_gcm());

    unsigned char* shared_key = NULL;
    NEW(shared_key, new unsigned char[keylen], "shared secret");
    memcpy(shared_key, digest, keylen);
    free_crypto(digest, digestlen);
    free_crypto(skey, skeylen);
    *seq_number = 0;

    // Free previous key
    free_crypto(key, keylen);
    cout << "Shared key updated" << endl;
    return shared_key;
}

bool list_command(int fd, unsigned char** key, uint32_t* seq_number){
    int nmessages;
    vector<string> files;

    int err = send_message(fd, *key, LIST_REQ,"", seq_number);
    if(err == 0){
        cout << "Fail to send list command" << endl;
        return false;
    }

    command_t msg_type = read_authenticated_msg(fd, *key, seq_number);
    if(msg_type != LIST_DONE && msg_type != LIST_RSP){
        error_msg_type("Fail to list files", msg_type);
        return false;
    }
    string plaintext = "";
    while(msg_type != LIST_DONE){
        if(*seq_number >= (UINT32_MAX - UPDATE_KEY_LIMIT)){
            // Update session key
            cout << "Key needs to be changed" << endl;
            *key = update_key(fd, *key, seq_number);
            if(!*key){
                cout << "Update key failed" << endl;
                return false;
            }
        }
        // Get server response with the number of message to read
        msg_type = read_message(fd, *key, plaintext, seq_number);
        if(msg_type != LIST_RSP && msg_type != LIST_DONE){
            error_msg_type("Fail to list files", msg_type);
            return false;
        }
     
        files.push_back(plaintext);
    }

    if(files.size()==0)
        cout << "Storage is empty. Upload some files with upload command!" << endl;
    else{
        // Printing files
        auto iter = files.begin();
        while(iter != files.end()){
            cout << "-> " << *iter << endl;
            iter++;
        }
    }
    return true;
}

bool delete_command(int fd, unsigned char* key, uint32_t* seq_number){
    cout << "Enter the filename to delete: ";
    string file;
    command_t msg_type;
    getline(cin, file);
    if(!cin) { cerr << "Error during input\n"; return false; }

    // checking filename
    if(!check_string(file)){
        cout << "Filename not valid." << endl;
        return true;
    }
    if(file.size() > FILENAME_SIZE) file.resize(FILENAME_SIZE);

    int err = send_message(fd, key, DELETE_REQ, file, seq_number);
    if (err == 0){
        cout << "Cannot send delete request" << endl;
        return false;
    }

    msg_type = read_authenticated_msg(fd, key, seq_number);
    if(msg_type != DELETE_CONFIRM){
        error_msg_type("Cannot proceed with delete", msg_type);
        return true;
    }
    // File exists, need to confirm or abort
    cout << "Are you sure you want to delete \"" << file << "\"? [y/n]" << endl;
    getline(cin , file);
    if(!cin) { cerr << "Error during input\n"; return false; }
    while((file.compare("y")!=0) && (file.compare("n")!=0)){
        cout << "Just type y or n to complete the request"<<endl;
        getline(cin, file);
        if(!cin) { cerr << "Error during input\n"; return false; }
    }

    if (file.compare("n") == 0){
        // Abort
        err = send_authenticated_msg(fd, key, DELETE_ABORT, seq_number);
        if(err == 0){
            cout << "Fail to send delete command" << endl;
            return false;
        }
        else cout << "Aborted. No file deleted" << endl;
        return true;
    }

    err = send_authenticated_msg(fd, key, DELETE_OK, seq_number);
    if(err == 0){
        cout << "Fail to send delete command" << endl;
        return false;
    }

    msg_type = read_authenticated_msg(fd, key, seq_number);
    if(msg_type != DELETE_OK){
        error_msg_type("Cannot delete file on the server", msg_type);
        return false;
    }

    cout << "File successfully deleted!" << endl;
    return true;
}

bool upload_command(int fd, unsigned char* key, uint32_t* seq_number){
    // Asking for the file to updload
    cout<<"Enter the filename to upload: ";
    string filename;
    getline(cin, filename);
    if(!cin) { cerr << "Error during input\n"; return false; }

    // checking filename
    if(!check_string(filename)){
        cout << "Filename not valid." << endl;
        return true;
    }
    if(filename.size() > FILENAME_SIZE) filename.resize(FILENAME_SIZE);

    string filepath = STORAGE_PATH + filename;
    // canonicalizing path
    char* canon_file = realpath(filepath.c_str(), NULL);
    if(canon_file){
        if(strncmp(canon_file, STORAGE_PATH.c_str(), strlen(STORAGE_PATH.c_str())) != 0) { 
            // Unauthorized path!
            free(canon_file); 
            // File do not exist
            cout << "Invalid path detected" << endl;
            if(send_authenticated_msg(fd, key, OP_FAIL, seq_number)==0)
                return false;
            return true;
        }
        free(canon_file); 
    }

    uint64_t file_len; // make it int
    uint32_t fragments = 0;

    //check if file exist locally
    FILE* file = fopen(filepath.c_str(),"r");
    if(!file){
        cout << "File do not exists" << endl;
        return true;
    }
    else{
        fseek(file,0,SEEK_END);
        // taking file len
        file_len = (ftell(file) > UINT32_MAX)? 0: ftell(file);
        if(!file_len){
            cout << "Empty file or over 4GB." << endl;
            fclose(file);
            return true;
        }
    }
   
    fseek(file, 0, SEEK_SET);
    // Sending request to server
    int err = send_message(fd, key, UPLOAD_REQ, filename, seq_number);
    if (err == 0){
        cout << "Cannot send the upload request." << endl;
        fclose(file);
        return false;
    }
    command_t msg_type = read_authenticated_msg(fd, key, seq_number);
    if(msg_type != UPLOAD_ACK){
        fclose(file);
        if(msg_type != NOT_VALID_FILE){
            cout << "Error in file upload" << endl;
            return false;
        }
        cout << "Cannot upload such file" << endl;
        return true;
    }
    // Checks are ok, sending the request to the server
    // We need to split the file to smaller fragment of fixed lenght
    fragments = file_len/MAX_FRAGMENT_SIZE + (file_len % MAX_FRAGMENT_SIZE != 0);
    const auto progress_level = static_cast<int>(fragments*0.01);

    // Upload the file
    cout << "Uploading " << '"'<<filename<<'"' << " with " << fragments << " frags" << endl;
    unsigned char* data;
    unsigned int data_len;
    msg_type = UPLOAD_FRGM; 
    int progress;
    for (int i = 0; i< fragments; i++){
        if(fragments == 1){
            msg_type = UPLOAD_END;
            NEW(data, new unsigned char[file_len], "Allocating data file");
            fread(data,1,file_len,file);
            data_len = file_len;
        } else if (i == fragments - 1){
            msg_type = UPLOAD_END;
            NEW(data, new unsigned char[file_len%MAX_FRAGMENT_SIZE], "Allocating data file");
            fread(data,1,(file_len%MAX_FRAGMENT_SIZE),file);
            data_len = file_len%MAX_FRAGMENT_SIZE;
        } else {
            NEW(data, new unsigned char[MAX_FRAGMENT_SIZE], "Allocating data file");
            fread(data,1,MAX_FRAGMENT_SIZE,file);
            data_len = MAX_FRAGMENT_SIZE;
            (progress_level != 0) ? progress = static_cast<int>(i/progress_level) : progress = 100;
            if(progress <= 100)
                cout << "\r [" << std::setw(4) << progress << "%] " << "Uploading..." << std::flush;
        }
        
        int err = send_data_message(fd, key, msg_type, data, data_len, seq_number);
        delete [] data;
        if (err == 0){
            cout << "Upload failed" << endl;
            fclose(file);
            return false;
        }
    }
    fclose(file);
    
    msg_type = read_authenticated_msg(fd, key, seq_number);
    if(msg_type == OP_FAIL){
        cout << "Something went wrong during upload..." << endl;
        return false;
    } else if (msg_type != UPLOAD_DONE){
        cout << "Upload operation failed" << endl;
        return false;
    } else cout << "File uploaded!" << endl;
    return true;
}

bool download_command(int fd, unsigned char* key, uint32_t* seq_number){
    // Asking for the file to download
    cout<<"Enter the filename to download: ";
    string filename, data;
    getline(cin, filename);
    if(!cin) { cerr << "Error during input\n"; return false; }

    // checking filename
    if(!check_string(filename)){
        cout << "Filename not valid." << endl;
        return true;
    }
    if(filename.size() > FILENAME_SIZE) filename.resize(FILENAME_SIZE);

    string filepath = STORAGE_PATH + filename;

    // canonicalizing path
    char* canon_file = realpath(filepath.c_str(), NULL);
    if(canon_file){
        if(strncmp(canon_file, STORAGE_PATH.c_str(), strlen(STORAGE_PATH.c_str())) != 0) { 
            // Unauthorized path!
            free(canon_file); 
            // File do not exist
            cout << "Invalid path detected" << endl;
            if(send_authenticated_msg(fd, key, OP_FAIL, seq_number)==0)
                return false;
            return true;
        }
        free(canon_file); 
    }

    //send download request
    int err = send_message(fd, key, DOWNLOAD_REQ, filename, seq_number);
    if (err == 0){
        cout << "Cannot send the download request." << endl;
        return false;
    }

    //wait for server response
    unsigned char* plaintext;
    int pt_len = 0;
    command_t msg_type = read_authenticated_msg(fd, key, seq_number);
    if (msg_type != DOWNLOAD_ACK){
        if(msg_type != NOT_VALID_FILE && msg_type != NO_SUCH_FILE){
            cout << "Error while downloading" << endl;
            return false;
        }
        error_msg_type("Fail to download file", msg_type);
        return true;
    } else{
        FILE* file = fopen(filepath.c_str(), "w+");
        if(!file){
            cout << "Something went wrong while opening file" << endl;
            return false;
        }
        int i = 0, dl_index=1;
        // get downalod fragments
        while(msg_type != DOWNLOAD_END){
            msg_type = read_data_message(fd, key, &plaintext, &pt_len, seq_number);
            if(msg_type == OP_FAIL){
                fclose(file);
                return false;
            }
            fwrite(plaintext, 1, pt_len, file);
            delete [] plaintext;
            i++;
            if(i%DOWNLOAD_PROGRESS==0){
                cout << "\r Downloading" << std::string(dl_index,'.') << std::flush;
                dl_index++;
            }
        }
        cout << "Download completed!" << endl;
        fclose(file);
        return true;
    }
}

bool rename_command(int fd, unsigned char* key, uint32_t* seq_number){
    cout << "Enter file to rename: ";
    string old_file;
    getline(cin, old_file);
    if(!cin) { cerr << "Error during input\n"; return false; }

    // checking filename
    if(!check_string(old_file)){
        cout << "Filename not valid." << endl;
        return true;
    }
    if(old_file.size() > FILENAME_SIZE) old_file.resize(FILENAME_SIZE);

    // sending request to server
    int err = send_message(fd, key, RENAME_REQ, old_file, seq_number);
    if (err == 0){
        cout << "Request to server failed." << endl;
        return false;
    }

    // Check response
    command_t msg_type = read_authenticated_msg(fd, key, seq_number);
    if(msg_type != RENAME_ACK){
        error_msg_type("Cannot proceed with rename operation", msg_type);
        return true;
    }
    // File is valid and exists on server
    cout << "Enter new file name: ";
    string new_filename;
    getline(cin, new_filename);
    if(!cin) { 
        cerr << "Error during input\n";
        send_message(fd, key, OP_FAIL, old_file, seq_number);
        return false; 
    }

    // checking filename
    if(!check_string(new_filename)){
        cout << "Filename not valid." << endl;
        send_message(fd, key, RENAME_FAIL, old_file, seq_number);
        return true;
    }
    if(new_filename.size() > FILENAME_SIZE) new_filename.resize(FILENAME_SIZE);

    // New filename is ok, sending to server
    err = send_message(fd, key, RENAME_REQ, new_filename, seq_number);
    if (err == 0){
        cout << "Request to server failed." << endl;
        return false;
    }

    // Get server response
    msg_type = read_authenticated_msg(fd, key, seq_number);
    if(msg_type != RENAME_OK){
        error_msg_type("Something went wrong. File not renamed", msg_type);
        return true;
    }
    
    cout << "File renamed!" << endl;
    return true;
}

void show_welcome_msg(){


    cout << "\n" << "╋╋╋┏┓╋╋╋╋╋╋╋╋┏┓╋╋╋┏┓ \n"
    "╋╋╋┃┃╋╋╋╋╋╋╋╋┃┃╋╋┏┛┗┓ \n"
    "┏━━┫┃┏━━┳┓┏┳━┛┃┏━┻┓┏╋━━┳━┳━━┳━━┳━━┓ \n"
    "┃┏━┫┃┃┏┓┃┃┃┃┏┓┃┃━━┫┃┃┏┓┃┏┫┏┓┃┏┓┃┃━┫ \n"
    "┃┗━┫┗┫┗┛┃┗┛┃┗┛┃┣━━┃┗┫┗┛┃┃┃┏┓┃┗┛┃┃━┫ \n"
    "┗━━┻━┻━━┻━━┻━━┛┗━━┻━┻━━┻┛┗┛┗┻━┓┣━━┛ \n"
    "╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋┏━┛┃ \n"
    "╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋┗━━┛ \n"
    "╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋┏┓╋╋╋╋╋╋╋┏┓ \n"
    "╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋┃┃╋╋╋╋╋╋┏┛┗┓ \n"
    "╋╋╋╋╋╋╋╋╋╋╋╋╋┏━━┫┃┏┳━━┳━╋┓┏┛ \n"
    "┏━━┳━━┳━━┳━━┓┃┏━┫┃┣┫┃━┫┏┓┫┃╋┏━━┳━━┳━━┳━━┳━━┓ \n"
    "┗━━┻━━┻━━┻━━┛┃┗━┫┗┫┃┃━┫┃┃┃┗┓┗━━┻━━┻━━┻━━┻━━┛ \n"
    "╋╋╋╋╋╋╋╋╋╋╋╋╋┗━━┻━┻┻━━┻┛┗┻━┛ \n" << endl;

    char esc_char = 27; // the decimal code for escape character is 27

    cout << "Cloud Storage Client\n"
    "Command list\n"
    << esc_char << "[1m" <<  "\t- list" << esc_char << "[0m" << " shows available files in your storage\n"
    << esc_char << "[1m" <<  "\t- upload" << esc_char << "[0m" << " copy a local file in your remote storage\n"
    << esc_char << "[1m" <<  "\t- download" << esc_char << "[0m" << " copy a remote file in your local storage\n"
    << esc_char << "[1m" <<  "\t- rename" << esc_char << "[0m" << " rename a file in your remote storage\n"
    << esc_char << "[1m" <<  "\t- delete" << esc_char << "[0m" << " remove a file in your remote storage\n"
    << esc_char << "[1m" <<  "\t- logout" << esc_char << "[0m" << " gracefully exit the application\n"
    << esc_char << "[1m" <<  "\t- help" << esc_char << "[0m" << " show this message\n" << endl;
}  

void help_msg(){
    char esc_char = 27; // the decimal code for escape character is 27
    cout << "Command list\n"
    << esc_char << "[1m" <<  "\t- list" << esc_char << "[0m" << " shows available files in your storage\n"
    << esc_char << "[1m" <<  "\t- upload" << esc_char << "[0m" << " copy a local file in your remote storage\n"
    << esc_char << "[1m" <<  "\t- download" << esc_char << "[0m" << " copy a remote file in your local storage\n"
    << esc_char << "[1m" <<  "\t- rename" << esc_char << "[0m" << " rename a file in your remote storage\n"
    << esc_char << "[1m" <<  "\t- delete" << esc_char << "[0m" << " remove a file in your remote storage\n"
    << esc_char << "[1m" <<  "\t- logout" << esc_char << "[0m" << " gracefully exit the application\n"
    << esc_char << "[1m" <<  "\t- help" << esc_char << "[0m" << " show this message\n" << endl;
    cout << "Need more help? Type a command or enter to skip" << endl;
    
    map<string,int> commands;
    commands.insert(pair<string,int>("list",LIST));
    commands.insert(pair<string,int>("upload", UPLOAD));
    commands.insert(pair<string,int>("download",DOWNLOAD));
    commands.insert(pair<string,int>("rename",RENAME));
    commands.insert(pair<string,int>("delete",DELETE));
    commands.insert(pair<string,int>("logout",LOGOUT));
    commands.insert(pair<string,int>("help",HELP));

    string command;
    getline(cin, command);
    if(!cin) { return; }
    for(int i=0; i<command.length(); i++)
        command[i] = tolower(command[i]);
    if(!strictly_check_string(command))
        return;
    

    switch(commands[command]) {
        case LIST:{
            cout << "\tCommand used to retrive the list of files stored in the server" << endl;
            break;
        }
        case UPLOAD:{
            cout << "\t<filename>: requires a file to copy on your remote storage. File must be available locally." << endl;
            break;
        }
        case DOWNLOAD:{
            cout << "\t<filename>: requires a file to copy on your locale storage. File must be available in remote storage." << endl;
            break;
        }
        case RENAME:{
            cout << "\t<old filename>: requires the name of file to be renamed. It must be available in remote storage.\n"
            << "\t<new filename>: the new filename." << endl;
            break;
        }
        case DELETE:{
            cout << "\tfilename>: requires the name of file to be deleted. It must be available in remote storage." << endl;
            break;
        }
        case LOGOUT:{
            cout << "\tTerminates client application." << endl;
            break;
        }
        default: {
            cout << "Command does not exists" << endl;
            break;
        }
    }
}