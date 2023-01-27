#include <cstring>
#include <string>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
// PER SOCKET
#include <sys/socket.h>
#include <netinet/in.h>
// PER THREAD
#include <pthread.h>
#include <mutex>
#include <vector>
#include <signal.h>
#include "../Common/utils.h"
#include "../Common/crypto.h"


#define PORT 4333

string SERVER_STORAGE;
string SERVER_HOME;     
string CERTIFICATE_PATH;
string SRV_PRIVKEY_PATH;

void configure_server();
bool new_online_user(string username, int* status);
bool disconnect_user(string username, int* status);

// Update set of fds
int update_set(fd_set set, int fd_num);
void *manage_client(void *arg);

// Operations
bool list(int fd, string username, unsigned char **key, uint32_t* seq_number);
bool delete_file(int fd, string username, unsigned char *key, uint32_t* seq_number, string data);
bool upload_file(int fd, string username, unsigned char *key, uint32_t* seq_number, string data);
bool download_file(int fd, string username, unsigned char *key, uint32_t* seq_number, string filename);
bool rename_file(int fd, string username, unsigned char *key, uint32_t* seq_number, string data);


unsigned char* handshake(int fd, string &username, int* status);
void handshake_error(int fd, string reason_msg);
unsigned char* update_key(int fd, unsigned char* key, uint32_t* seq_number);

std::mutex mtx_online_users;
vector<string> online_users;

map<string,string> registered_users;

static sigset_t _sigset;
static sigset_t _sigpipe;
// allow to stop threads on signals
volatile sig_atomic_t stop = 0;

void* signal_handler(void* arg);

int main(){
    int server_skt;
    struct sockaddr_in address;

    sigemptyset(&_sigset);
    sigemptyset(&_sigpipe);
    sigaddset(&_sigpipe, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &_sigpipe, NULL);
    sigaddset(&_sigset, SIGINT);
    pthread_sigmask(SIG_BLOCK, &_sigset, NULL);

    pthread_t clientThread;

    // Spawn signal thread
    if (pthread_create(&clientThread, NULL, &signal_handler, NULL)){
        cout << "Errore creazione del signal thread" << endl;
    }
    pthread_detach(clientThread);

    configure_server();
    
    if ((server_skt = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_skt, (struct sockaddr *)&address, sizeof(address)) < 0){
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_skt, SOMAXCONN) < 0){
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    fd_set set, read_set;
    int fd_num = 0, fd, client_skt, nread; // max active fd

    if (server_skt > fd_num)
        fd_num = server_skt;
    FD_ZERO(&set);
    FD_SET(server_skt, &set);
    struct timeval time;
    cout << "Waiting for connections..." << endl;
    while (stop==0){
        time.tv_sec = 5;
		time.tv_usec = 0;
        read_set = set;
        if (select(fd_num + 1, &read_set, NULL, NULL, &time) < 0){   
            if (stop) break;
            else{
                close(server_skt);
                perror("Error during select");
                exit(EXIT_FAILURE);
            }
        }
        for (fd = 3; fd <= fd_num; fd++){
            if (FD_ISSET(fd, &read_set)){
                if (fd == server_skt){
                    // connection socket ready
                    client_skt = accept(server_skt, NULL, 0);
                    FD_SET(client_skt, &set);
                    if (client_skt > fd_num)
                        fd_num = client_skt;
                    cout << "New connection accepted!" << endl;
                }
                else
                    client_skt = fd;
                // Spawn new thread to manage client
                if (pthread_create(&clientThread, NULL, &manage_client, (void *)&client_skt)){
                    cout << "Error while creating new thread" << endl;
                    close(client_skt);
                }
                pthread_detach(clientThread);
                FD_CLR(client_skt, &set);
                if ((fd_num = update_set(set, fd_num)) < 0){
                    perror("Update set failed");
                    close(fd);
                    exit(EXIT_FAILURE);
                }
            }
        }
    }
    cout << "\nTerminating server, good bye!" << endl;
    close(server_skt);
}

void* signal_handler(void* arg){
    int x;
    while(stop == 0){
        // waiting signal
        if(sigwait(&_sigset, &x)!=0){
            perror("sigwait");
            exit(EXIT_FAILURE);
        }
        stop = 1;
    }
    pthread_exit(0);
}

void configure_server(){
    char cwd[256];
    if(getcwd(cwd, 256)==NULL) exit(EXIT_FAILURE);

    SERVER_HOME = (string)cwd;
    SERVER_STORAGE = SERVER_HOME + (string)"/Storage/";
    CERTIFICATE_PATH = SERVER_HOME + (string)"/CloudStorage_cert.pem";
    SRV_PRIVKEY_PATH = SERVER_HOME + (string)"/CloudStorage_key.pem";

    string config_file_path = SERVER_HOME + (string)"/config/config.txt";
    fstream fp; 
    fp.open(config_file_path.c_str(), ios::in);
    if(fp.is_open()){
        string line;
        while(getline(fp, line)){
            if(line[0] == '#') continue; // skip comment
            string username;
            string path_to_pubkey;
            size_t pos;
            if ((pos = line.find(" ")) == string::npos){
                // error
                cerr << "ERROR: wrong configuration file. Please check README." << endl;
                fp.close();
                return;
            }
            username = line.substr(0,pos);
            path_to_pubkey = line.substr(pos+1, line.size());
            registered_users.insert(pair<string, string>(username, path_to_pubkey));
        }
    }
    else{ perror("cannot configure server"); exit(EXIT_FAILURE); }
    fp.close();
    // Allocate "dedicated storage" for each registered user
    DIR* storage_dir;
    storage_dir = opendir(SERVER_STORAGE.c_str());
    if(!storage_dir){
        // we need to create the directory
        if(mkdir(SERVER_STORAGE.c_str(), 0754)==-1){ //only read to others
            perror("Storage directory");
            exit(EXIT_FAILURE);
        }
    }
    closedir(storage_dir);
    // directory exists: creating subfolders for each registered users
    auto iter = registered_users.begin();
    while(iter != registered_users.end()){
        string user_storage = iter->first;
        storage_dir = opendir((SERVER_STORAGE + user_storage).c_str());
        if(!storage_dir){
            if(mkdir((SERVER_STORAGE + user_storage).c_str(), 0754)==-1){
                perror("User storage directory");
                exit(EXIT_FAILURE);
            }
        }
        closedir(storage_dir);
        ++iter;
    }
}

bool new_online_user(string username, int* status){
    try{
        registered_users.at(username);
    }
    catch(std::out_of_range){
        cout << "User " << username << " not registered" << endl;
        return false;
    }
    mtx_online_users.lock();
    auto iter = online_users.begin();
    bool found = false;
    while(!found && iter != online_users.end()){
        if (username.compare(*iter) == 0) found = true;
        iter++;
    }
    if(!found){
        // new online user
        online_users.push_back(username);
        *status = 1;
        mtx_online_users.unlock();
        return true;
    }
    // already online;
    mtx_online_users.unlock();
    return false;
}

bool disconnect_user(string username, int* status){
    mtx_online_users.lock();
    auto iter = online_users.begin();
    while(iter != online_users.end()){
        if (username.compare(*iter) == 0){
            online_users.erase(iter);
            *status=0;
            mtx_online_users.unlock();
            return true;
        }
        iter++;
    }
    mtx_online_users.unlock();
    return false;
}

int update_set(fd_set set, int fd_num){
    for (int i = (fd_num - 1); i >= 0; --i)
        if (FD_ISSET(i, &set))
            return i;
    return -1;
}

void *manage_client(void *arg){
    int fd = *((int *)arg);
    int logged_in;
    int err;
    string username = "";
    
    unsigned char* key = handshake(fd, username, &logged_in);

    if(!key){
        if (!username.empty())
            disconnect_user(username, &logged_in); 
        close(fd);
        pthread_exit(0); 
    }

    cout << "\nHandshake successful" << endl;

    int keylen = EVP_CIPHER_key_length(EVP_aes_128_gcm());
    uint32_t seq_number = 0;
    command_t msg_type;
    string data = "";

    while (logged_in && stop==0){
        // Check if a key update is needed (to avoid seq number wrap around)
        if(seq_number >= (UINT32_MAX - UPDATE_KEY_LIMIT)){
            // Update session key
            cout << "Key needs to be changed" << endl;
            key = update_key(fd, key, &seq_number);
            if(!key){
                cout << "Update key failed" << endl;
                disconnect_user(username, &logged_in);
                break;
            }
        }
        msg_type = read_message(fd, key, data, &seq_number);
        if (msg_type == OP_FAIL){
            cout << "Failed to read message... terminating thread" << endl;
            disconnect_user(username, &logged_in);
            break;
        }
        switch (msg_type){
            case LIST_REQ:{
                cout << "Request to list files" << endl;
                if(!list(fd, username, &key, &seq_number))
                    disconnect_user(username, &logged_in);
                break;
            }
            case DELETE_REQ:{
                cout << "Requesting to delete " << data << endl;
                if(!delete_file(fd, username, key, &seq_number, data))
                    disconnect_user(username, &logged_in);
                break;
            }
            case RENAME_REQ:{
                cout << "Requesting to rename file " << data << endl;
                if(!rename_file(fd, username, key, &seq_number, data))
                    disconnect_user(username, &logged_in);
                break;
            }
            case UPLOAD_REQ:{
                cout << "Request to upload file " << data << endl;
                if(!upload_file(fd, username, key, &seq_number, data))
                    disconnect_user(username, &logged_in);
                break;
            }
            case DOWNLOAD_REQ:{
                cout << "Request to download file " << data << endl;
                if(!download_file(fd, username, key, &seq_number, data))
                    disconnect_user(username, &logged_in);
                break;
            }
            case LOGOUT:{
                if(disconnect_user(username, &logged_in))
                    cout << "User " << username << " disconnected!" << endl;
                else{
                    cout << "Failed to disconnect user " << username << ", terminating" << endl;
                    free_crypto(key, keylen);
                    close(fd);
                    pthread_exit(0);
                } 
                break;
            }
            default:
                break;
        }
    }
    // FREE CRYPTO MATERIAL
    free_crypto(key, keylen);
    close(fd);
    pthread_exit(0);
}

unsigned char* handshake(int fd, string &username, int* status){

    int err;
    uint32_t signature_len, handshake_msg_len;
    unsigned char* clt_nonce = NULL;
    unsigned char *srv_nonce = NULL;
    unsigned char* shared_key = NULL;
    unsigned char* signature = NULL;
    unsigned char* cert_buf = NULL;
    unsigned char* pubkey_buf = NULL;
    unsigned char* handshake_msg = NULL;
    unsigned char* error_msg = NULL;

    EVP_PKEY* prvkey = NULL;
    EVP_PKEY *my_dhkey = NULL;
    X509* srv_cert = NULL;
    command_t msg_type;
    bool handshake_finished = false;
    bool error_occurred = false;

    while(!handshake_finished && !error_occurred){
        err = read_udata(fd, &handshake_msg, &handshake_msg_len);
        if(err == 0) { error_occurred = true; break; }
        // Get message type
        memcpy(&msg_type, handshake_msg, sizeof(command_t));

        switch(msg_type){
            case HANDSHAKE_PH1: {

                /* ------------------------------------------------------------------------------------ */
                /* FIRST PHASE: Server receives CLT_nonce and CLT_username                              */
                /* ------------------------------------------------------------------------------------ */

                NEW(clt_nonce, new unsigned char[NONCE_LEN], "client nonce");
                memcpy(clt_nonce, handshake_msg + sizeof(command_t), NONCE_LEN);

                uint32_t username_len;
                memcpy(&username_len, handshake_msg + sizeof(command_t) + NONCE_LEN, sizeof(uint32_t));

                char* clt_username;
                if(username_len == UINT32_MAX){
                    //cannot increment
                    cout << "Overflow error" << endl;
                    handshake_error(fd, "Server error");
                    error_occurred = true; 
                    break;
                }

                NEW(clt_username, new char[(username_len+1)], "client username");
                memcpy(clt_username, handshake_msg + sizeof(command_t) + NONCE_LEN + sizeof(uint32_t), username_len);
                clt_username[username_len] = '\0';
                username = (string)clt_username;

                delete [] handshake_msg;
                if (!new_online_user(username, status)){
                    cout << "User not registered or already online" << endl;
                    handshake_error(fd, "User not registered or already online");
                    error_occurred = true; 
                    break;
                }

                cout << "Handshaking with " << username << endl;
                /* ------------------------------------------------------------------------------------ */
                /* Second phase SERVER EXCHANGE.                                                        */
                /* Server generates SRV_nonce, load the certtificate and compute the EECDH              */
                /* Compute signature with server's RSA private key as:                                  */
                /*                  Sign(RSAprv, EECHD || CLT_nonce || SRV_nonce)                       */
                /* ------------------------------------------------------------------------------------ */

                NEW(srv_nonce, new unsigned char[NONCE_LEN], "server nonce");
                generate_random(srv_nonce, NONCE_LEN);

                srv_cert = get_certificate(CERTIFICATE_PATH);
                if(!srv_cert){
                    cout << "ERRORE srv_cert" << endl;
                    handshake_error(fd, "Server error");
                    error_occurred = true; break;
                }

                // Generate ephimeral DH
                my_dhkey = generate_pubkey();
                if(!my_dhkey){
                    cout << "ERRORE mydhkey" << endl;
                    handshake_error(fd, "Server error");
                    error_occurred = true; break;
                }

                uint32_t cert_buf_len = serialize_certificate(fd, srv_cert, &cert_buf);
                if (cert_buf_len == 0){
                    cout << "ERRORE cert buf len" << endl;
                    handshake_error(fd, "Server error");
                    error_occurred = true; break;
                }

                X509_free(srv_cert); srv_cert = NULL;

                uint32_t pubkey_buf_len = serialize_pubkey(fd, my_dhkey, &pubkey_buf);
                if (pubkey_buf_len == 0){
                    cout << "ERRORE pubkey_buf_len" << endl;
                    handshake_error(fd, "Server error");
                    error_occurred = true; break;
                }

                // Read server privkey
                FILE* prvkey_file = fopen(SRV_PRIVKEY_PATH.c_str(), "r");
                if(!prvkey_file){ 
                    cout << "ERRORE prvkey file" << endl;
                    handshake_error(fd, "Server error");
                    error_occurred = true; break;
                }

                prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
                fclose(prvkey_file);
                if(!prvkey){
                    cout << "ERRORE prvkey" << endl;
                    handshake_error(fd, "Server error");
                    error_occurred = true; break;
                }

                uint32_t to_sign_len;
                if(!unsigned_math("sum", pubkey_buf_len, (NONCE_LEN*2), &to_sign_len)){
                    cout << "Overflow error" << endl;
                    handshake_error(fd, "Server error");
                    error_occurred = true; break;
                }

                unsigned char* to_sign; NEW(to_sign, new unsigned char[to_sign_len], "to sign buffer");
                memcpy(to_sign, pubkey_buf, pubkey_buf_len);
                memcpy(to_sign + pubkey_buf_len, clt_nonce, NONCE_LEN);
                memcpy(to_sign + pubkey_buf_len + NONCE_LEN, srv_nonce, NONCE_LEN);

                NEW(signature, new unsigned char[EVP_PKEY_size(prvkey)], "signature buffer");
                signature_len = sign(prvkey, to_sign, to_sign_len, signature);
                if(signature_len == 0){
                    cout << "ERRORE signature len" << endl;
                    delete [] to_sign;
                    delete [] signature;
                    handshake_error(fd, "Server error");
                    error_occurred = true; break;
                }

                delete [] to_sign;
                EVP_PKEY_free(prvkey); prvkey = NULL;

                msg_type = HANDSHAKE_PH2;
                bool ok_math = true && unsigned_math("sum",(sizeof(command_t) + (NONCE_LEN*2) + (sizeof(uint32_t)*3)), cert_buf_len, &handshake_msg_len);
                ok_math = ok_math && unsigned_math("sum", handshake_msg_len, pubkey_buf_len, &handshake_msg_len);
                ok_math = ok_math && unsigned_math("sum", handshake_msg_len, signature_len, &handshake_msg_len);
                if(!ok_math){
                    cout << "Overflow error" << endl;
                    delete [] signature;
                    handshake_error(fd, "Server error");
                    error_occurred = true; break;
                }
                
                // < msg_type, serv_cert_len, eecdh_len, signature_len, Certificate, EECDH, Signature >
                NEW(handshake_msg, new unsigned char[handshake_msg_len], "handshake message");
                memcpy(handshake_msg, &msg_type, sizeof(command_t));
                memcpy(handshake_msg + sizeof(command_t), srv_nonce, NONCE_LEN);
                memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN, clt_nonce, NONCE_LEN);
                memcpy(handshake_msg + sizeof(command_t) + (NONCE_LEN*2), &cert_buf_len, sizeof(uint32_t));
                memcpy(handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + sizeof(uint32_t), &pubkey_buf_len, sizeof(uint32_t));
                memcpy(handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(uint32_t)*2), &signature_len, sizeof(uint32_t));
                memcpy(handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(uint32_t)*3), cert_buf, cert_buf_len);
                memcpy(handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(uint32_t)*3) + cert_buf_len, pubkey_buf, pubkey_buf_len);
                memcpy(handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(uint32_t)*3) + cert_buf_len + pubkey_buf_len, signature, signature_len);

                delete [] cert_buf; cert_buf = NULL;
                delete [] pubkey_buf; pubkey_buf = NULL;
                delete [] signature; signature = NULL;

                if(send_udata(fd, handshake_msg, handshake_msg_len) == 0){
                    error_occurred = true; break;
                }
                
                delete [] handshake_msg;
                break;
            }
            case HANDSHAKE_PH3:{

                /* ------------------------------------------------------------------------------------ */
                /* Third phase: CLIENT EXCHANGE.                                                        */
                /* Verify SRV_nonce, client signature and derive the shared key                         */
                /* ------------------------------------------------------------------------------------ */

                unsigned char* received_srv_nonce;
                NEW(received_srv_nonce, new unsigned char[NONCE_LEN], "received srv nonce");
                memcpy(received_srv_nonce, handshake_msg + sizeof(command_t), NONCE_LEN);

                if(CRYPTO_memcmp(srv_nonce, received_srv_nonce, NONCE_LEN)!=0){
                    cout << "Detect different nonces, abort" << endl;
                    // nonces are different, abort
                    handshake_error(fd, "Nonces are different");
                    error_occurred = true; break;
                }

                uint32_t clt_pubkey_len;
                memcpy(&clt_pubkey_len, handshake_msg + sizeof(command_t) + NONCE_LEN, sizeof(uint32_t));
                memcpy(&signature_len, handshake_msg + sizeof(command_t) + NONCE_LEN + sizeof(uint32_t), sizeof(uint32_t));
                
                unsigned char* clt_pubkey_buf; NEW(clt_pubkey_buf, new unsigned char[clt_pubkey_len], "server public key");
                memcpy(clt_pubkey_buf, handshake_msg + sizeof(command_t) + NONCE_LEN + (sizeof(uint32_t)*2), clt_pubkey_len);

                EVP_PKEY* clt_dh_pubkey = deserialize_pubkey(clt_pubkey_buf, clt_pubkey_len);
                if(!clt_dh_pubkey){
                    cout << "ERROR: Deserialization of public key" << endl;
                    handshake_error(fd, "Server error");
                    delete [] clt_pubkey_buf;
                    error_occurred = true; break;
                }

                // Read signature
                NEW(signature, new unsigned char[signature_len], "server signature");
                memcpy(signature, handshake_msg + sizeof(command_t) + NONCE_LEN + (sizeof(uint32_t)*2) + clt_pubkey_len, signature_len);

                // We need to verify signature
                uint32_t to_verify_len;
                if(!unsigned_math("sum", clt_pubkey_len, (NONCE_LEN*2), &to_verify_len)){
                    cout << "Overflow error" << endl;
                    handshake_error(fd, "Server error");
                    delete [] clt_pubkey_buf;
                    error_occurred = true; break;
                }

                unsigned char* to_verify; NEW(to_verify, new unsigned char[to_verify_len], "to_verify buffer");
                memcpy(to_verify, clt_pubkey_buf, clt_pubkey_len);
                memcpy(to_verify + clt_pubkey_len, clt_nonce, NONCE_LEN);
                memcpy(to_verify + clt_pubkey_len + NONCE_LEN, srv_nonce, NONCE_LEN);

                delete [] clt_nonce; clt_nonce = NULL;
                delete [] srv_nonce; srv_nonce = NULL;
                delete [] clt_pubkey_buf;
                delete [] handshake_msg;

                // read client rsa public key
                // First read server privkey
                string path = registered_users.at(username);
                FILE* clt_rsa_pubkey_file = fopen(path.c_str(), "r");
                if(!clt_rsa_pubkey_file){ 
                    cout << "Errore rsa pubkey file" << endl;
                    handshake_error(fd, "Server error");
                    delete [] signature;
                    delete [] to_verify;
                    EVP_PKEY_free(clt_dh_pubkey); 
                    error_occurred = true; break;
                }

                EVP_PKEY* rsa_clt_pubkey = PEM_read_PUBKEY(clt_rsa_pubkey_file, NULL, NULL, NULL);
                fclose(clt_rsa_pubkey_file);
                if(!rsa_clt_pubkey){
                    cout << "Error reading rsa client pubkey" << endl;
                    handshake_error(fd, "Server error");
                    delete [] signature;
                    delete [] to_verify;
                    EVP_PKEY_free(clt_dh_pubkey); 
                    error_occurred = true; break;
                }

                int verify = verify_signature(rsa_clt_pubkey, to_verify, to_verify_len, signature, signature_len);
                if (verify == 0){
                    cout << "ERRORE Signature verification FAILED" << endl;
                    handshake_error(fd, "Signature verification failed");
                    delete [] signature;
                    delete [] to_verify;
                    EVP_PKEY_free(clt_dh_pubkey);
                    EVP_PKEY_free(rsa_clt_pubkey); 
                    error_occurred = true;
                    break;
                }

                delete [] to_verify;
                delete [] signature;
                EVP_PKEY_free(rsa_clt_pubkey);

                // Derive the shared secret
                unsigned char* skey = NULL;
                uint32_t skeylen = derive_shared_secret(my_dhkey, clt_dh_pubkey, &skey);
                if (skeylen == 0){
                    cout << "ERRORE skeylen" << endl;
                    handshake_error(fd, "Server error");
                    EVP_PKEY_free(clt_dh_pubkey);
                    error_occurred = true;
                    break;
                }

                EVP_PKEY_free(clt_dh_pubkey);
                // Using SHA-256 to extract a safe key!
                unsigned char* digest; 
                NEW(digest, new unsigned char[EVP_MD_size(EVP_sha256())], "digest for secret key");
                uint32_t digestlen = hash_secret(digest, skey, skeylen);
                if (digestlen == 0){
                    cout << "ERRORE digestlen" << endl;
                    handshake_error(fd, "Server error");
                    free_crypto(skey, skeylen);
                    delete [] digest;
                    error_occurred = true; break;
                }

                int keylen = EVP_CIPHER_key_length(EVP_aes_128_gcm());
                NEW(shared_key, new unsigned char[keylen], "shared secret");
                memcpy(shared_key, digest, keylen);

                free_crypto(digest, digestlen);
                free_crypto(skey, skeylen);
                handshake_finished = true;
                break;
            }
            case HANDSHAKE_ERR: {
                
                uint32_t reason_len;
                memcpy(&reason_len, handshake_msg + sizeof(command_t), sizeof(uint32_t));

                char *reason; NEW(reason, new char[reason_len+1], "reason msg");
                memcpy(reason, handshake_msg + sizeof(command_t)+ sizeof(uint32_t), reason_len);
                
                reason[reason_len] = '\0';
                cout << "Something went wrong during handshake: " << reason << endl;

                delete [] reason;
                delete [] handshake_msg;
                error_occurred = true; 
                break;
            }
            default: {
                cout << "Handshake command not recognized" << endl;
                error_occurred = true; 
                break;
            }
        }
    }   
    
    if(error_occurred){
        cout << "Error in handshake" << endl;
        if(clt_nonce) delete [] clt_nonce;
        if(srv_nonce) delete [] srv_nonce;
        if(cert_buf) delete [] cert_buf;
        if(pubkey_buf) delete [] pubkey_buf;
        if(prvkey) EVP_PKEY_free(prvkey);
        if(my_dhkey) EVP_PKEY_free(my_dhkey);
        if(srv_cert) X509_free(srv_cert);
        return NULL;
    }

    return shared_key;
}

void handshake_error(int fd, string reason_msg){
    command_t msg_type = HANDSHAKE_ERR;
    uint32_t reason_len = reason_msg.size();
    uint32_t error_msg_len = sizeof(command_t) + sizeof(uint32_t) + reason_len;
    unsigned char* _error_msg = NULL;
    NEW(_error_msg, new unsigned char[error_msg_len], "error message");
    memcpy(_error_msg, &msg_type, sizeof(command_t));
    memcpy(_error_msg + sizeof(command_t), &reason_len, sizeof(uint32_t));
    memcpy(_error_msg + sizeof(command_t) + sizeof(uint32_t),reason_msg.c_str(), reason_len);
    send_udata(fd, _error_msg, error_msg_len);
    delete [] _error_msg;
    return;
}

unsigned char* update_key(int fd, unsigned char* key, uint32_t* seq_number){
    // Reading update key request
    command_t msg_type = read_authenticated_msg(fd, key, seq_number);
    if(msg_type != UPDATE_KEY_REQ){
        send_authenticated_msg(fd, key, OP_FAIL, seq_number);
        return NULL;
    }

    int err = send_authenticated_msg(fd, key, UPDATE_KEY_ACK, seq_number);
    if(err == 0) return NULL;

    // Now we can start the new exchange
    unsigned char* update_key_msg = NULL;
    unsigned char* pubkey_buf = NULL;
    unsigned char* clt_pubkey_buf = NULL;
    uint32_t clt_pubkey_len;
    EVP_PKEY* clt_dh_pubkey = NULL;
    EVP_PKEY* my_dhkey = NULL;
    
    // Generate ephimeral DH
    my_dhkey = generate_pubkey();
    if(!my_dhkey){
        cout << "ERRORE mydh key" << endl;
        return NULL;
    }

    uint32_t pubkey_buf_len = serialize_pubkey(fd, my_dhkey, &pubkey_buf);
    if (pubkey_buf_len == 0){
        cout << "ERRORE pubkey buf len" << endl;
        return NULL;
    }

    msg_type = read_data_message(fd, key, &clt_pubkey_buf, &clt_pubkey_len, seq_number);
    if(msg_type == OP_FAIL){
        return NULL;
    }

    clt_dh_pubkey = deserialize_pubkey(clt_pubkey_buf, clt_pubkey_len);
    if(!clt_dh_pubkey){
        cout << "Errore dh srv" << endl;
        return NULL;
    }

    err = send_data_message(fd, key, UPDATE_KEY_REQ, pubkey_buf, pubkey_buf_len, seq_number);
    if (err == 0) return NULL;

    delete [] clt_pubkey_buf;
    delete [] pubkey_buf;

    // Derive new shared secret
    unsigned char* skey;
    uint32_t skeylen = derive_shared_secret(my_dhkey, clt_dh_pubkey, &skey);
    if (skeylen == 0){
        cout << "ERRORE skeylen" << endl;
        return NULL;
    }

    // Using SHA-256 to extract a safe key!
    unsigned char* digest; 
    NEW(digest, new unsigned char[EVP_MD_size(EVP_sha256())], "digest for secret key");
    uint32_t digestlen = hash_secret(digest, skey, skeylen);
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

    free_crypto(key, keylen);
    cout << "Shared key updated" << endl;
    return shared_key;
}

bool list(int fd, string username, unsigned char **key, uint32_t* seq_number){
    string path = SERVER_STORAGE + username + (string)"/";
    vector<string> files;
    DIR *dir;
    struct dirent *diread;
    int err, nfiles = 0;
    if ((dir = opendir(path.c_str())) != NULL){
        while ((diread = readdir(dir)) != NULL){
            if (strncmp(diread->d_name, ".", 1) != 0 && strncmp(diread->d_name, "..", 2) != 0){
                files.push_back(diread->d_name);
                if (nfiles == INT_MAX) break;
                nfiles++;
            }
        }
        closedir(dir);
    }
    else{
        cout << "Failed to open the user directory" << endl;
        send_authenticated_msg(fd, *key, OP_FAIL, seq_number);
        return false;
    }
    command_t msg_type = (nfiles>0) ? LIST_RSP : LIST_DONE;
    // Send list response
    err = send_authenticated_msg(fd, *key, msg_type, seq_number);
    if(err == 0){
        cout << "Fail to send list response" << endl;
        return false;
    }
    auto iter = files.begin();
    while(nfiles > 0){
        // Check if a key update is needed (to avoid seq number wrap around)
        if(*seq_number >= (UINT32_MAX - UPDATE_KEY_LIMIT)){
            // Update session key
            cout << "Key needs to be changed" << endl;
            *key = update_key(fd, *key, seq_number);
            if(!*key){
                cout << "Update key failed" << endl;
                return false;
            }
        }
        if(nfiles == 1) msg_type = LIST_DONE;
        err = send_message(fd, *key, msg_type, *iter, seq_number);
        if (err == 0){
            cout << "Fail to send list item" << endl;
            return false;
        }
        iter++;
        nfiles--;
    }
    cout << "Sent list of files" << endl;
    return true;
}

bool delete_file(int fd, string username, unsigned char *key, uint32_t* seq_number, string data){
    // checking data
    if(!check_string(data)){
        cout << "Filename not valid." << endl;
        if(send_authenticated_msg(fd, key, NOT_VALID_FILE, seq_number)==0)
            return false;
        return true;
    }

    string path = SERVER_STORAGE + username + (string)"/" + data;
    string ok_dir = SERVER_STORAGE + username;
    // canonicalizing path
    char* canon_file = realpath(path.c_str(), NULL);
    if(canon_file){
        if(strncmp(canon_file, ok_dir.c_str(), strlen(ok_dir.c_str())) != 0) { 
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

    FILE* file = fopen(path.c_str(), "r");
    if(!file){
        // File do not exist
        cout << "File do not exists" << endl;
        if(send_authenticated_msg(fd, key, NO_SUCH_FILE, seq_number)==0)
            return false;
        return true;
    }
    else fclose(file);

    // File exist, asking for confirmation
    if(send_authenticated_msg(fd, key, DELETE_CONFIRM, seq_number)==0){
        cout << "Cannot send delete confirmation" << endl;
        return false;
    }

    // Read client's reply
    command_t msg_type = read_authenticated_msg(fd, key, seq_number);
    if(msg_type != DELETE_OK && msg_type != DELETE_ABORT){
        send_authenticated_msg(fd, key, OP_FAIL, seq_number);
        cout << "Client's reply not recognized" << endl;
        return false;
    }

    if(msg_type == DELETE_ABORT){
        cout << "\"" << data <<"\": deletion cancelled" << endl;
        return true;
    }
   
    // here we can delete file
    if (remove(path.c_str()) != 0){
        // Something went wrong
        send_authenticated_msg(fd, key, OP_FAIL, seq_number);
        cout << "Error while deleting file" << endl;
        return false;
    }   

    if(send_authenticated_msg(fd, key, DELETE_OK, seq_number)==0){
        cout << "Cannot send confirmation for deleting file" << endl;
        return false;
    }

    return true;
}

bool upload_file(int fd, string username, unsigned char *key, uint32_t* seq_number, string data){
    // validate filename
    if(!check_string(data)){
        cout << "Filename not valid. Got: " << data << endl;
        if(send_authenticated_msg(fd, key, NOT_VALID_FILE, seq_number)==0)
            return false;
        return true;
    }

    string filepath = SERVER_STORAGE + username + (string)"/" + data;
    string ok_dir = SERVER_STORAGE + username;
    // canonicalizing path
    char* canon_file = realpath(filepath.c_str(), NULL);
    if(canon_file){
        if(strncmp(canon_file, ok_dir.c_str(), strlen(ok_dir.c_str())) != 0) { 
            // Unauthorized path!
            free(canon_file); 
            cout << "Invalid path detected" << endl;
            if(send_authenticated_msg(fd, key, NOT_VALID_FILE, seq_number)==0)
                return false;
            return true;
        }
        free(canon_file); 
    }

    uint32_t pt_len = 0;
    unsigned char* plaintext;
    command_t msg_type = UPLOAD_REQ;
    FILE* file = fopen(filepath.c_str(), "wb+");
    if(!file){
        cout << "Cannot create file" << endl;
        send_authenticated_msg(fd, key, OP_FAIL, seq_number);
        return false;
    }
    if(send_authenticated_msg(fd, key, UPLOAD_ACK, seq_number)==0){
        fclose(file);
        return false;
    }
    while(msg_type != UPLOAD_END){
        msg_type = read_data_message(fd, key, &plaintext, &pt_len, seq_number);
        if(msg_type == OP_FAIL){
            fclose(file);
            remove(filepath.c_str());
            return false;
        }
        fwrite(plaintext, 1, pt_len, file);
        delete [] plaintext;
    }
    fclose(file);
    // Upload finished
    int err = send_authenticated_msg(fd, key, UPLOAD_DONE, seq_number);
    if(err == 0){
        cout << "Fail to send upload done command" << endl;
        return false;
    }

    return true;
}

bool download_file(int fd, string username, unsigned char *key, uint32_t* seq_number, string filename){
    // validate filename
    if(!check_string(filename)){
        cout << "Filename not valid. Got: " << filename << endl;
        if(send_authenticated_msg(fd, key, NOT_VALID_FILE, seq_number)==0)
            return false;
        return true;
    }

    long int file_len;
    uint32_t fragments = 0;
    
    string filepath = SERVER_STORAGE + username + (string)"/" + filename;
    string ok_dir = SERVER_STORAGE + username;
    // canonicalizing path
    char* canon_file = realpath(filepath.c_str(), NULL);
    if(canon_file){
        if(strncmp(canon_file, ok_dir.c_str(), strlen(ok_dir.c_str())) != 0) { 
            // Unauthorized path!
            free(canon_file); 
            // File do not exist
            cout << "Invalid path detected" << endl;
            if(send_authenticated_msg(fd, key, NOT_VALID_FILE, seq_number)==0)
                return false;
            return true;
        }
        free(canon_file); 
    }

    FILE* file = fopen(filepath.c_str(),"rb");
    if(!file){
        cout << "File do not exists" << endl;
        if(send_authenticated_msg(fd, key, NO_SUCH_FILE, seq_number)==0)
            return false;
        return true;
    }
    else{
        fseek(file,0,SEEK_END);
        // taking file len
        file_len = (ftell(file) > UINT32_MAX)? 0: ftell(file);
        if(!file_len){
            cout << "Empty file or over 4GB." << endl;
            fclose(file);
            if(send_authenticated_msg(fd, key, NOT_VALID_FILE, seq_number)==0)
                return false;
            return true;
        }
    }
   
    fseek(file, 0, SEEK_SET);
    // Checks are ok, send file to client.
    // Need to split the file to smaller fragment of fixed lenght
    fragments = file_len/MAX_FRAGMENT_SIZE + (file_len % MAX_FRAGMENT_SIZE != 0);
    int err = send_authenticated_msg(fd, key, DOWNLOAD_ACK, seq_number);
    if(err == 0){
        cout << "Fail to send download ack command" << endl;
        fclose(file);
        return false;
    }
    const auto progress_level = static_cast<int>(fragments*0.01);
    // Send file
    cout << "Sending " << '"'<< filename <<'"' << " with " << fragments << " frags" << endl;
    uint32_t data_len;
    unsigned char* data;
    command_t msg_type = DOWNLOAD_FRGM; 
    int progress;
    for (int i = 0; i< fragments; i++){
        if(fragments == 1){
            msg_type = DOWNLOAD_END;
            NEW(data, new unsigned char[file_len], "Allocating data file");
            fread(data,1,file_len,file);
            data_len = file_len;
        } else if (i == fragments - 1){
            msg_type = DOWNLOAD_END;
            NEW(data, new unsigned char[file_len%MAX_FRAGMENT_SIZE], "Allocating data file");
            fread(data,1,(file_len%MAX_FRAGMENT_SIZE),file);
            data_len = file_len%MAX_FRAGMENT_SIZE;
        } else {
            NEW(data, new unsigned char[MAX_FRAGMENT_SIZE], "Allocating data file");
            fread(data,1,MAX_FRAGMENT_SIZE,file);
            data_len = MAX_FRAGMENT_SIZE;
            (progress_level != 0) ? progress = static_cast<int>(i/progress_level) : progress = 100;
            if(progress <= 100)
                cout << "\r [" << std::setw(4) << progress << "%] " << "Sending..." << std::flush;
        }
        
        int err = send_data_message(fd, key, msg_type, data, data_len, seq_number);
        delete [] data;
        if (err == 0){
            cout << "Download failed" << endl;
            fclose(file);
            return false;
        }
    }
    fclose(file);
    cout << "File correctly sent!" << endl;
    return true;
}

bool rename_file(int fd, string username, unsigned char *key, uint32_t* seq_number, string data){
    // validate old filename
    if(!check_string(data)){
        cout << "Filename not valid. Got: " << data << endl;
        if(send_authenticated_msg(fd, key, NOT_VALID_FILE, seq_number)==0)
            return false;
        return true;
    }

    string old_path = SERVER_STORAGE + username + (string)"/" + data;
    string ok_dir = SERVER_STORAGE + username;
    // canonicalizing path
    char* canon_file = realpath(old_path.c_str(), NULL);
    if(canon_file){
        if(strncmp(canon_file, ok_dir.c_str(), strlen(ok_dir.c_str())) != 0) { 
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

    FILE* file = fopen(old_path.c_str(),"r");
    if(!file){
        cout << "File do not exists" << endl;
        if(send_authenticated_msg(fd, key, NO_SUCH_FILE, seq_number)==0)
            return false;
        return true;
    }
    fclose(file);

    // File exists, proceeding with rename operation
    if(send_authenticated_msg(fd, key, RENAME_ACK, seq_number)==0)
        return false;

    // Get new filename from client
    string new_file = "";
    command_t msg_type = read_message(fd, key, new_file, seq_number);
    if (msg_type != RENAME_REQ){
        cout << "Rename operation failed." << endl;
        if(msg_type == OP_FAIL) return false;
        else return true;
    }

    // validate new filename
    if(!check_string(new_file)){
        cout << "Filename not valid. Got: " << new_file << endl;
        if(send_authenticated_msg(fd, key, NOT_VALID_FILE, seq_number)==0)
            return false;
        return true;
    }
    string new_path = SERVER_STORAGE + username + (string)"/" + new_file;
    // canonicalizing path
    canon_file = realpath(new_path.c_str(), NULL);
    if(canon_file){
        if(strncmp(canon_file, ok_dir.c_str(), strlen(ok_dir.c_str())) != 0) { 
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

    // Check if the same file exists in current storage
    file = fopen(new_path.c_str(),"r");
    if(file){
        fclose(file);
        // File already exists, cannot rename
        cout << "File already exists." << endl;
        if(send_authenticated_msg(fd, key, FILE_ALREADY, seq_number)==0)
            return false;
        return true;
    }
    // Proceed with renaming
    int err = rename(old_path.c_str(), new_path.c_str());
    if (err != 0){
        // Rename failed
        send_authenticated_msg(fd, key, OP_FAIL, seq_number);
        cout << "Fail to rename file "<< data << endl;
        return false;
    }

    // Send result to client
    err = send_authenticated_msg(fd, key, RENAME_OK, seq_number);
    if(err == 0){
        cout << "Fail to send result to client" << endl;
        return false;
    }
    cout << "Successfully renamed file" << endl;
    return true;
}

void show_help_msg(){
    cout << "\n" << "╋╋╋┏┓╋╋╋╋╋╋╋╋┏┓╋╋╋┏┓ \n"
    "╋╋╋┃┃╋╋╋╋╋╋╋╋┃┃╋╋┏┛┗┓ \n"
    "┏━━┫┃┏━━┳┓┏┳━┛┃┏━┻┓┏╋━━┳━┳━━┳━━┳━━┓ \n"
    "┃┏━┫┃┃┏┓┃┃┃┃┏┓┃┃━━┫┃┃┏┓┃┏┫┏┓┃┏┓┃┃━┫ \n"
    "┃┗━┫┗┫┗┛┃┗┛┃┗┛┃┣━━┃┗┫┗┛┃┃┃┏┓┃┗┛┃┃━┫ \n"
    "┗━━┻━┻━━┻━━┻━━┛┗━━┻━┻━━┻┛┗┛┗┻━┓┣━━┛ \n"
    "╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋┏━┛┃ \n"
    "╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋┗━━┛ \n"
    "╋╋╋╋╋╋╋╋╋╋╋╋╋┏━━┳━━┳━┳┓┏┳━━┳━┓ \n"
    "┏━━┳━━┳━━┳━━┓┃━━┫┃━┫┏┫┗┛┃┃━┫┏┻━┳━━┳━━┳━━┳━━┓ \n"
    "┗━━┻━━┻━━┻━━┛┣━━┃┃━┫┃┗┓┏┫┃━┫┣━━┻━━┻━━┻━━┻━━┛ \n"
    "╋╋╋╋╋╋╋╋╋╋╋╋╋┗━━┻━━┻┛╋┗┛┗━━┻┛ \n" << endl;
}