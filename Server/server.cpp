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
#include <map>
#include <signal.h>
#include "../Common/utils.h"
#include "../Common/crypto.h"

#define PORT 4333
#define SERVER_HOME "./"
#define SERVER_STORAGE "./Storage/"
#define CERTIFICATE_PATH "CloudStorage_cert.pem"
#define SRV_PRIVKEY_PATH "CloudStorage_key.pem"

void configure_server();
bool new_online_user(string username);
bool disconnect_user(string username);

// Update set of fds
int update_set(fd_set set, int fd_num);
void *manage_client(void *arg);

vector<string> extract_params(string message);
// Operations
void list(int fd, string username, unsigned char *key, int* seq_number);

unsigned char* handshake(int fd, string &username);

std::mutex mtx_online_users;
vector<string> online_users;

map<string,string> registered_users;

static sigset_t _sigset;
static sigset_t _sigpipe;
volatile sig_atomic_t stop = 0;

void* signal_handler(void* arg);

int main()
{
    int server_skt; // il socket è un file descriptor?
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
    
    if ((server_skt = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_skt, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_skt, SOMAXCONN) < 0)
    {
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
    while (stop==0)
    {
        time.tv_sec = 5;
		time.tv_usec = 0;
        read_set = set;
        if (select(fd_num + 1, &read_set, NULL, NULL, &time) < 0)
        {   
            if (stop) break;
            else{
                close(server_skt);
                perror("Error during select");
                exit(EXIT_FAILURE);
            }
        }
        for (fd = 3; fd <= fd_num; fd++)
        {
            if (FD_ISSET(fd, &read_set))
            {
                if (fd == server_skt)
                {
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
                if (pthread_create(&clientThread, NULL, &manage_client, (void *)&client_skt))
                {
                    cout << "Errore creazione del thread" << endl;
                    close(client_skt);
                }
                pthread_detach(clientThread);
                FD_CLR(client_skt, &set);
                if ((fd_num = update_set(set, fd_num)) < 0)
                {
                    perror("Update set failed");
                    close(fd);
                    exit(EXIT_FAILURE);
                }
                /*
                else {
                    // I/O sock ready
                    cout << "fd: " << fd << " is ready!" << endl;
                    fflush(stdout);
                    nread = read(fd, buf, 1024);
                    if(nread==0){
                        cout << "Closing connection of " << fd << endl;
                        // EOF
                        FD_CLR(fd, &set);
                        if((fd_num = update_set(set, fd_num))<0){
                            perror("Update set failed");
                            close(fd);
                            exit(EXIT_FAILURE);
                        }
                        close(fd);
                    } else{
                        cout << buf << "\n";
                    }
                }
                */
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
    string config_file_path = SERVER_HOME + (string)"config/config.txt";
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
    storage_dir = opendir(SERVER_STORAGE);
    if(!storage_dir){
        // we need to create the directory
        if(mkdir(SERVER_STORAGE, 0774)==-1){
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
            if(mkdir((SERVER_STORAGE + user_storage).c_str(), 0644)==-1){
                perror("User storage directory");
                exit(EXIT_FAILURE);
            }
        }
        closedir(storage_dir);
        ++iter;
    }
}

bool new_online_user(string username){
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
        mtx_online_users.unlock();
        return true;
    }
    // already online;
    mtx_online_users.unlock();
    return false;
}

bool disconnect_user(string username){
    mtx_online_users.lock();
    auto iter = online_users.begin();
    while(iter != online_users.end()){
        if (username.compare(*iter) == 0){
            online_users.erase(iter);
            mtx_online_users.unlock();
            return true;
        }
        iter++;
    }
    mtx_online_users.unlock();
    return false;
}

int update_set(fd_set set, int fd_num)
{
    for (int i = (fd_num - 1); i >= 0; --i)
        if (FD_ISSET(i, &set))
            return i;
    return -1;
}

void *manage_client(void *arg)
{
    int fd = *((int *)arg);
    int logged_in = 1;
    int message_type, err;
    string username = "";

    // Possible commands
    map<string, int> commands;
    commands.insert(pair<string, int>("list", LIST));
    commands.insert(pair<string, int>("upload", UPLOAD));
    commands.insert(pair<string, int>("download", DOWNLOAD));
    commands.insert(pair<string, int>("rename", RENAME));
    commands.insert(pair<string, int>("delete", DELETE));
    commands.insert(pair<string, int>("logout", LOGOUT));

    unsigned char* key = handshake(fd, username);
    if(!key){
        if (!username.empty())
            disconnect_user(username); 
        close(fd);
        pthread_exit(0); 
    }
    int keylen = EVP_CIPHER_key_length(EVP_aes_128_gcm());
    int seq_number = 0;
    command_t msg_type;
    unsigned char *message_tmp = NULL;
    int msg_len;
    vector<string> message;
    
    while (logged_in && stop==0){
        // <command param1 .... paramN>
        /*msg_type = my_read_message(fd, key, &message_tmp, &seq_number);
        if (msg_type == OP_FAIL){
            cout << "Failed to read message... terminating thread" << endl;
            disconnect_user((string)username);
            break;
        }*/
        msg_type = read_authenticated_msg(fd, key, &seq_number);
        if (msg_type == OP_FAIL){
            cout << "Failed to read message... terminating thread" << endl;
            disconnect_user((string)username);
            break;
        }
        switch (msg_type){
            case LIST_REQ:{
                // ----> forse è da reinserire *(message_tmp + CLR_FRAGMENT - 1) = '\0';
                /*message = extract_params(string((char *)message_tmp));
                // qui la richiesta è già decifrata
                if (message.size() == 0)
                {
                    delete[] message_tmp;
                    continue;
                }*/
                list(fd, (string)username, key, &seq_number);
                break;
            }
            case LOGOUT:{
                logged_in = 0;
                if(disconnect_user((string)username))
                    cout << "User " << username << " disconnected!" << endl;
                else cout << "Failed to disconnect user " << username << ", terminating" << endl;  
                break;
            }
            default:
                break;
        }
        //delete[] message_tmp;
    }

    free_crypto(key, keylen);
    close(fd);
    pthread_exit(0);
}

unsigned char* handshake(int fd, string &username){

    int err, size;
    unsigned char* clt_nonce = NULL;
    unsigned char *srv_nonce = NULL;
    unsigned char* shared_key = NULL;
    unsigned char* signature = NULL;
    unsigned char* cert_buf = NULL;
    unsigned char* pubkey_buf = NULL;
    int signature_len;
    EVP_PKEY* prvkey = NULL;
    EVP_PKEY *my_dhkey = NULL;
    X509* srv_cert = NULL;
    command_t msg_type;
    bool handshake_finished = false;
    bool error_occurred = false;

    while(!handshake_finished && !error_occurred){
        err = readn(fd, &msg_type, sizeof(command_t));
        if(err <= 0) { error_occurred = true; break; }
        switch(msg_type){
            case HANDSHAKE_REQ: {

                /* ------------------------------------------------------------------------------------ */
                /* FIRST PHASE: Server receives client nonce and username                               */
                /* ------------------------------------------------------------------------------------ */

                printf("------------------------ FASE 1 ------------------------\n");

                NEW(clt_nonce, new unsigned char[NONCE_LEN], "client nonce");

                err = readn(fd, clt_nonce, NONCE_LEN);
                if(err <= 0) { error_occurred = true; break; }

                int username_len;
                err = readn(fd, &username_len, sizeof(int));
                if(err <= 0) { error_occurred = true; break; }
                cout << "Received " << username_len << endl;
                char* clt_username;
                NEW(clt_username, new char[(username_len+1)], "client username");
                err = readn(fd, clt_username, username_len);
                if(err <= 0) { error_occurred = true; break; }
                clt_username[username_len] = '\0';
                // USERNAME SANIFICATION
                username.append(clt_username);

                if (!new_online_user(username)){
                    // user not registered or already online
                    msg_type = HANDSHAKE_ERR;
                    error_occurred = true; 
                    string error_msg = "User not registered or already online";
                    int error_size = error_msg.size()+1;
                    writen(fd, &msg_type, sizeof(command_t));
                    writen(fd, &error_size, sizeof(int));
                    writen(fd, (void*)error_msg.c_str(), error_size);
                    break;
                }

                NEW(srv_nonce, new unsigned char[NONCE_LEN], "server nonce");
                generate_random(srv_nonce, NONCE_LEN);

                msg_type = HANDSHAKE_PH1;
                err = writen(fd, &msg_type, sizeof(command_t));
                if(err <= 0) { error_occurred = true; break; }
                
                err = writen(fd, srv_nonce, NONCE_LEN);
                if(err <= 0) { error_occurred = true; break; }

                // FORSE c'è da inviare prima la size per la stringa username
                printf("Client nonce: \n");
                BIO_dump_fp (stdout, (const char *)clt_nonce, NONCE_LEN);
                printf("Server nonce: \n");
                BIO_dump_fp (stdout, (const char *)srv_nonce, NONCE_LEN);
                cout << "Client username: " << username << endl;
                fflush(NULL);

                /* ------------------------------------------------------------------------------------ */
                /* Second phase SERVER EXCHAGE.                                                         */
                /* Server sends certificate                                                             */
                /* Generete Ephimeral DH params, encrypt it with private server RSA key, send it        */
                /* Generate signature, send it                                                          */
                /* ------------------------------------------------------------------------------------ */

                printf("------------------------ FASE 2 ------------------------\n");

                srv_cert = get_certificate(CERTIFICATE_PATH);
                if(!srv_cert){
                    cout << "ERRORE srv_cert" << endl;
                    error_occurred = true; break;
                }

                // Generate ephimeral DH
                my_dhkey = generate_pubkey();
                if(!my_dhkey){
                    cout << "ERRORE mydhkey" << endl;
                    error_occurred = true; break;
                }

                int cert_buf_len = serialize_certificate(fd, srv_cert, &cert_buf);
                if (cert_buf_len == 0){
                    cout << "ERRORE cert buf len" << endl;
                    error_occurred = true; break;
                }

                X509_free(srv_cert); srv_cert = NULL;
                //printf("Server certificate: \n");
                //BIO_dump_fp (stdout, (const char *)cert_buf, cert_buf_len);

                int pubkey_buf_len = serialize_pubkey(fd, my_dhkey, &pubkey_buf);
                if (pubkey_buf_len == 0){
                    cout << "ERRORE pubkey_buf_len" << endl;
                    error_occurred = true; break;
                }

                //printf("Server DH Pubkey: \n");
                //BIO_dump_fp (stdout, (const char *)pubkey_buf, pubkey_buf_len);

                // First read server privkey
                FILE* prvkey_file = fopen(SRV_PRIVKEY_PATH, "r");
                if(!prvkey_file){ 
                    cout << "ERRORE prvkey file" << endl;
                    error_occurred = true; break;
                }

                prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
                fclose(prvkey_file);
                if(!prvkey){
                    cout << "ERRORE prvkey" << endl;
                    error_occurred = true; break;
                }

                int to_sign_len = cert_buf_len + pubkey_buf_len + (NONCE_LEN*2);
                unsigned char* to_sign; NEW(to_sign, new unsigned char[to_sign_len], "to sign buffer");
                memcpy(to_sign, cert_buf, cert_buf_len);
                memcpy(to_sign + cert_buf_len, pubkey_buf, pubkey_buf_len);
                memcpy(to_sign + cert_buf_len + pubkey_buf_len, clt_nonce, NONCE_LEN);
                memcpy(to_sign + cert_buf_len + pubkey_buf_len + NONCE_LEN, srv_nonce, NONCE_LEN);

                NEW(signature, new unsigned char[EVP_PKEY_size(prvkey)], "signature buffer");
                signature_len = sign(prvkey, to_sign, to_sign_len, signature);
                if(signature_len == 0){
                    cout << "ERRORE signature len" << endl;
                    delete [] to_sign;
                    delete [] signature;
                    error_occurred = true; break;
                }

                delete [] to_sign;
                EVP_PKEY_free(prvkey); prvkey = NULL;
                //printf("Server signature: \n");
                //BIO_dump_fp (stdout, (const char *)signature, signature_len);

                //printf("Plain signature: \n");
                //BIO_dump_fp (stdout, (const char *)to_sign, to_sign_len);

                msg_type = HANDSHAKE_PH2;
                err = writen(fd, &msg_type, sizeof(command_t));
                if (err <= 0){
                    delete [] signature;
                    error_occurred = true; break;
                }
                // Finally send: certificate, pubkey, signature
                // send certificate len
                err = writen(fd, &cert_buf_len, sizeof(int));
                if(err <= 0){
                    delete [] signature;
                    error_occurred = true; break;
                }
                err = writen(fd, cert_buf, cert_buf_len);
                if(err <= 0){
                    delete [] signature;
                    error_occurred = true; break;
                }
                delete [] cert_buf; cert_buf = NULL;

                err = writen(fd, &pubkey_buf_len, sizeof(int));
                if(err <= 0){
                    delete [] signature;
                    error_occurred = true; break;
                }
                err = writen(fd, pubkey_buf, pubkey_buf_len);
                if(err <= 0){
                    delete [] signature;
                    error_occurred = true; break;
                }
                delete [] pubkey_buf; pubkey_buf = NULL;

                err = writen(fd, &signature_len, sizeof(int));
                if(err <= 0){
                    delete [] signature;
                    error_occurred = true; break;
                }
                err = writen(fd, signature, signature_len);
                if(err <= 0){
                    delete [] signature;
                    error_occurred = true; break;
                }
                delete [] signature; signature = NULL;

                break;
            }
            case HANDSHAKE_PH3:{

                /* ------------------------------------------------------------------------------------ */
                /* THIRD PHASE CLIENT EXCHANGE.                                                         */
                /* Server sends certificate                                                             */
                /* Generete Ephimeral DH params, encrypt it with private server RSA key, send it        */
                /* Generate signature, send it                                                          */
                /* ------------------------------------------------------------------------------------ */
                
                printf("------------------------ FASE 3 ------------------------\n");

                int clt_pubkey_len;
                err = readn(fd, &clt_pubkey_len, sizeof(int));
                if(err <= 0){ error_occurred = true; break; }
                
                unsigned char* clt_pubkey_buf; NEW(clt_pubkey_buf, new unsigned char[clt_pubkey_len], "server public key");
                err = readn(fd, clt_pubkey_buf, clt_pubkey_len);
                if(err <= 0){
                    delete [] clt_pubkey_buf;
                    error_occurred = true; break;
                }

                // printf("Client DH Pubkey: \n");
                // BIO_dump_fp (stdout, (const char *)clt_pubkey_buf, clt_pubkey_len);

                EVP_PKEY* clt_dh_pubkey = deserialize_pubkey(clt_pubkey_buf, clt_pubkey_len);
                if(!clt_dh_pubkey){
                    cout << "ERROR: Deserialization of public key" << endl;
                    delete [] clt_pubkey_buf;
                    error_occurred = true; break;
                }

                // Read signature
                err = readn(fd, &signature_len, sizeof(int));
                if(err <= 0){
                    delete [] clt_pubkey_buf;
                    EVP_PKEY_free(clt_dh_pubkey); 
                    error_occurred = true; break;
                }

                NEW(signature, new unsigned char[signature_len], "server signature");
                err = readn(fd, signature, signature_len);
                if(err <= 0){
                    delete [] clt_pubkey_buf;
                    delete [] signature;
                    EVP_PKEY_free(clt_dh_pubkey); 
                    error_occurred = true; break;
                }

                // printf("Client signature: \n");
                // BIO_dump_fp (stdout, (const char *)signature, signature_len);

                // We need to verify signature
                int to_verify_len = clt_pubkey_len + (NONCE_LEN*2);
                unsigned char* to_verify; NEW(to_verify, new unsigned char[to_verify_len], "to_verify buffer");
                memcpy(to_verify, clt_pubkey_buf, clt_pubkey_len);
                memcpy(to_verify + clt_pubkey_len, clt_nonce, NONCE_LEN);
                memcpy(to_verify + clt_pubkey_len + NONCE_LEN, srv_nonce, NONCE_LEN);

                delete [] clt_nonce; clt_nonce = NULL;
                delete [] srv_nonce; srv_nonce = NULL;
                delete [] clt_pubkey_buf;

                // printf("Plain signature: \n");
                // BIO_dump_fp (stdout, (const char *)to_verify, to_verify_len);

                // read client rsa public key
                // First read server privkey
                string path = registered_users.at(username);
                FILE* clt_rsa_pubkey_file = fopen(path.c_str(), "r");
                if(!clt_rsa_pubkey_file){ 
                    cout << "Errore rsa pubkey file" << endl;
                    delete [] signature;
                    delete [] to_verify;
                    EVP_PKEY_free(clt_dh_pubkey); 
                    error_occurred = true; break;
                }

                EVP_PKEY* rsa_clt_pubkey = PEM_read_PUBKEY(clt_rsa_pubkey_file, NULL, NULL, NULL);
                fclose(clt_rsa_pubkey_file);
                if(!rsa_clt_pubkey){
                    cout << "Error reading rsa client pubkey" << endl;
                    delete [] signature;
                    delete [] to_verify;
                    EVP_PKEY_free(clt_dh_pubkey); 
                    error_occurred = true; break;
                }

                int verify = verify_signature(rsa_clt_pubkey, to_verify, to_verify_len, signature, signature_len);
                if (verify == 0){
                    cout << "ERRORE Signature verification FAILED" << endl;
                    // send error
                    delete [] signature;
                    delete [] to_verify;
                    EVP_PKEY_free(clt_dh_pubkey);
                    EVP_PKEY_free(rsa_clt_pubkey); 
                    error_occurred = true;
                    msg_type = HANDSHAKE_ERR;
                    string error_msg = "Signature verification FAILED";
                    int error_size = error_msg.size()+1;
                    writen(fd, &msg_type, sizeof(command_t));
                    writen(fd, &error_size, sizeof(int));
                    writen(fd, (void*)error_msg.c_str(), error_size);
                    break;
                }

                cout << "Signature verification: OK" << endl;

                delete [] to_verify;
                delete [] signature;
                EVP_PKEY_free(rsa_clt_pubkey);

                printf("------------------------ FASE 4 ------------------------\n");

                // Derive the shared secret
                unsigned char* skey = NULL;
                int skeylen = derive_shared_secret(my_dhkey, clt_dh_pubkey, &skey);
                if (skeylen == 0){
                    cout << "ERRORE skeylen" << endl;
                    EVP_PKEY_free(clt_dh_pubkey);
                    error_occurred = true;
                    break;
                }

                printf("Here it is the shared secret pre-hash: \n");
                BIO_dump_fp (stdout, (const char *)skey, skeylen);
                EVP_PKEY_free(clt_dh_pubkey);
                // Using SHA-256 to extract a safe key!
                unsigned char* digest; 
                NEW(digest, new unsigned char[EVP_MD_size(EVP_sha256())], "digest for secret key");
                int digestlen = hash_secret(digest, skey, skeylen);
                if (digestlen == 0){
                    cout << "ERRORE digestlen" << endl;
                    free_crypto(skey, skeylen);
                    delete [] digest;
                    error_occurred = true; break;
                }

                int keylen = EVP_CIPHER_key_length(EVP_aes_128_gcm());
                NEW(shared_key, new unsigned char[keylen], "shared secret");
                memcpy(shared_key, digest, keylen);

                printf("Here it is the shared secret: \n");
                BIO_dump_fp (stdout, (const char *)shared_key, keylen);
                free_crypto(digest, digestlen);
                free_crypto(skey, skeylen);
                handshake_finished = true;
                break;
            }
            case HANDSHAKE_ERR: {
                cout << "Something went wrong during handshake:" << endl;
                
                err = readn(fd, &size, sizeof(int));
                if (err <= 0){ error_occurred = true; break; }

                char *reason; NEW(reason, new char[size], "reason");
                err = readn(fd, reason, size);
                if (err <= 0){
                    delete [] reason;
                    error_occurred = true; break;
                }
                reason[size-1] = '\0';
                cout << reason << endl;
                delete [] reason;
                error_occurred = true; 
                break;
            }
            default: {
                cout << "Command not recognized" << endl;
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

vector<string> extract_params(string message){
    string delim = " ";
    vector<string> request;
    // CONTROLLARE LA STRINGA CON CANONICALIZATION E SANIFICATION
    size_t pos = 0;
    while ((pos = message.find(delim)) != string::npos)
    {
        request.push_back(message.substr(0, pos));
        message.erase(0, pos + delim.length());
    }
    if (!message.empty())
        request.push_back(message.substr(0, pos));

    return request;
}

void list(int fd, string username, unsigned char *key, int* seq_number){
    string path = SERVER_STORAGE + username + "/";
    vector<string> files;
    DIR *dir;
    struct dirent *diread;
    int err, nfiles = 0;
    if ((dir = opendir(path.c_str())) != NULL){
        while ((diread = readdir(dir)) != NULL){
            if (strncmp(diread->d_name, ".", 1) != 0 && strncmp(diread->d_name, "..", 2) != 0){
                files.push_back(diread->d_name);
                nfiles++;
            }
        }
        closedir(dir);
    }
    else{
        perror("opendir");
        // Manage error message
        /*if (dir == NULL) {
        id = 8; //ID di errore 
        plaintext = std::string("Cartella non trovata");
        plaintext.resize(SIZE_FILENAME);
        if(!send_std_packet(plaintext,key,sd,counter,id,1)){
            #pragma optimize("", off)
            memset(key, 0, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
            #pragma optimize("", on)
            free(key);
            disconnect(sd);
        }
        return;
    }*/
        return;
    }
    
    command_t msg_type = LIST_RSP;
    auto iter = files.begin();
    while(nfiles > 0){
        if(nfiles == 1) msg_type = LIST_DONE;
        err = send_message(fd, key, msg_type, *iter, seq_number);
        if (err == 0){
            // fail to send message
        }
        iter++;
        nfiles--;
    }

    return;
}