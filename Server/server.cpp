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
bool new_online_user(string username, int* status);
bool disconnect_user(string username, int* status);

// Update set of fds
int update_set(fd_set set, int fd_num);
void *manage_client(void *arg);

vector<string> extract_params(string message);
// Operations
void list(int fd, string username, unsigned char *key, int* seq_number);
void delete_file(int fd, string username, unsigned char *key, int* seq_number, string data);
void upload_file(int fd, string username, unsigned char *key, int* seq_number, string data);
void download_file(int fd, string username, unsigned char *key, int* seq_number, string filename);
void rename_file(int fd, string username, unsigned char *key, int* seq_number, string data);


unsigned char* handshake(int fd, string &username, int* status);
unsigned char* update_key(int fd, unsigned char* key, int* seq_number);

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
    int logged_in;
    int message_type, err;
    string username = "";

    unsigned char* key = handshake(fd, username, &logged_in);

    if(!key){
        if (!username.empty())
            disconnect_user(username, &logged_in); 
        close(fd);
        pthread_exit(0); 
    }
    int keylen = EVP_CIPHER_key_length(EVP_aes_128_gcm());
    int seq_number = 0;
    command_t msg_type;
    string data = "";
    unsigned char *message_tmp = NULL;
    int msg_len;
    vector<string> message;
    
    while (logged_in && stop==0){
        // Check if a key update is needed (to avoid seq number wrap around)
        if(seq_number >= (UINT32_MAX - UPDATE_KEY_LIMIT)){
            // Update session key
            cout << "Key needs to be changed" << endl;
            key = update_key(fd, key, &seq_number);
            cout << endl;
            cout << seq_number << endl;
        }
        // <command param1 .... paramN>
        /*msg_type = my_read_message(fd, key, &message_tmp, &seq_number);
        if (msg_type == OP_FAIL){
            cout << "Failed to read message... terminating thread" << endl;
            disconnect_user((string)username);
            break;
        }*/
        // msg_type = read_authenticated_msg(fd, key, &seq_number);
        msg_type = read_message(fd, key, data, &seq_number);
        if (msg_type == OP_FAIL){
            cout << "Failed to read message... terminating thread" << endl;
            disconnect_user(username, &logged_in);
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
                list(fd, username, key, &seq_number);
                break;
            }
            case DELETE_REQ:{
                cout << "Requesting to delete " << data << endl;
                delete_file(fd, username, key, &seq_number, data);
                break;
            }
            case RENAME_REQ:{
                cout << "Requesting to rename file " << data << endl;
                rename_file(fd, username, key, &seq_number, data);
                break;
            }
            case UPLOAD_REQ:{
                cout << "Request to upload file " << data << endl;
                upload_file(fd, username, key, &seq_number, data);
                break;
            }
            case DOWNLOAD_REQ:{
                cout << "Request to download file " << data << endl;
                download_file(fd, username, key, &seq_number, data);
                break;
            }
            case LOGOUT:{
                if(disconnect_user((string)username, &logged_in))
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

unsigned char* handshake(int fd, string &username, int* status){

    int err, size;
    unsigned char* clt_nonce = NULL;
    unsigned char *srv_nonce = NULL;
    unsigned char* shared_key = NULL;
    unsigned char* signature = NULL;
    unsigned char* cert_buf = NULL;
    unsigned char* pubkey_buf = NULL;
    int signature_len;
    unsigned char* handshake_msg = NULL;
    unsigned char* error_msg = NULL;
    int error_msg_len;
    int handshake_msg_len;
    EVP_PKEY* prvkey = NULL;
    EVP_PKEY *my_dhkey = NULL;
    X509* srv_cert = NULL;
    command_t msg_type;
    bool handshake_finished = false;
    bool error_occurred = false;

    while(!handshake_finished && !error_occurred){
        err = read_data(fd, &handshake_msg, &handshake_msg_len);
        if(err == 0) { error_occurred = true; break; }
        // Get message type
        memcpy(&msg_type, handshake_msg, sizeof(command_t));
        cout << "Received command: " << msg_type << endl;
        //err = readn(fd, &msg_type, sizeof(command_t));
        //if(err <= 0) { error_occurred = true; break; }
        switch(msg_type){
            case HANDSHAKE_PH1: {

                /* ------------------------------------------------------------------------------------ */
                /* FIRST PHASE: Server receives Client.nonce and username                               */
                /* ------------------------------------------------------------------------------------ */

                NEW(clt_nonce, new unsigned char[NONCE_LEN], "client nonce");
                memcpy(clt_nonce, handshake_msg + sizeof(command_t), NONCE_LEN);
            
                printf("Client nonce: \n");
                BIO_dump_fp (stdout, (const char *)clt_nonce, NONCE_LEN);

                int username_len;
                memcpy(&username_len, handshake_msg + sizeof(command_t) + NONCE_LEN, sizeof(int));
                cout << "Received " << username_len << endl;

                char* clt_username;
                NEW(clt_username, new char[(username_len+1)], "client username");
                memcpy(clt_username, handshake_msg + sizeof(command_t) + NONCE_LEN + sizeof(int), username_len);
                clt_username[username_len] = '\0';
                // USERNAME SANIFICATION
                username = (string)clt_username;
                cout << "Usernamne: " << username << "!" << endl; 

                delete [] handshake_msg;
                if (!new_online_user(username, status)){
                    cout << "Errore nello username" << endl;
                    // user not registered or already online
                    msg_type = HANDSHAKE_ERR;
                    error_occurred = true; 
                    string reason_msg = "User not registered or already online";
                    int reason_len = reason_msg.size();
                    error_msg_len = sizeof(command_t) + sizeof(int) + reason_len;
                    NEW(error_msg, new unsigned char[error_msg_len], "error message");
                    memcpy(error_msg, &msg_type, sizeof(command_t));
                    memcpy(error_msg + sizeof(command_t), &reason_len, sizeof(int));
                    memcpy(error_msg + sizeof(command_t) + sizeof(int),reason_msg.c_str(), reason_len);
                    send_data(fd, error_msg, error_msg_len);
                    delete [] error_msg;
                    break;
                }

                /* ------------------------------------------------------------------------------------ */
                /* Second phase SERVER EXCHANGE.                                                        */
                /* Server generates Server.nonce, load the certtificate and compute the EECDH           */
                /* Compute signature with server's RSA private key as:                                  */
                /*                  Sign(RSAprv, EECHD || Client.Nonce || Server.Nonce)                 */
                /* Fint handshake_msg_lennally it sends < Certificate, EECDH, Server.Nonce, Signature > */
                /* ------------------------------------------------------------------------------------ */

                NEW(srv_nonce, new unsigned char[NONCE_LEN], "server nonce");
                generate_random(srv_nonce, NONCE_LEN);

                printf("Server nonce: \n");
                BIO_dump_fp (stdout, (const char *)srv_nonce, NONCE_LEN);

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

                int pubkey_buf_len = serialize_pubkey(fd, my_dhkey, &pubkey_buf);
                if (pubkey_buf_len == 0){
                    cout << "ERRORE pubkey_buf_len" << endl;
                    error_occurred = true; break;
                }

                // Read server privkey
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

                int to_sign_len = pubkey_buf_len + (NONCE_LEN*2);
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
                    error_occurred = true; break;
                }

                delete [] to_sign;
                EVP_PKEY_free(prvkey); prvkey = NULL;

                //printf("Server signature: \n");
                //BIO_dump_fp (stdout, (const char *)signature, signature_len);
                cout << cert_buf_len << " " << pubkey_buf_len << " " << signature_len << endl;

                msg_type = HANDSHAKE_PH2;
                handshake_msg_len = sizeof(command_t) + (NONCE_LEN*2) + (sizeof(int)*3) + cert_buf_len + pubkey_buf_len + signature_len;
                // < msg_type, serv_cert_len, eecdh_len, signature_len, Certificate, EECDH, Signature >
                NEW(handshake_msg, new unsigned char[handshake_msg_len], "handshake message");
                memcpy(handshake_msg, &msg_type, sizeof(command_t));
                memcpy(handshake_msg + sizeof(command_t), srv_nonce, NONCE_LEN);
                memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN, clt_nonce, NONCE_LEN);
                memcpy(handshake_msg + sizeof(command_t) + (NONCE_LEN*2), &cert_buf_len, sizeof(int));
                memcpy(handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + sizeof(int), &pubkey_buf_len, sizeof(int));
                memcpy(handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(int)*2), &signature_len, sizeof(int));
                memcpy(handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(int)*3), cert_buf, cert_buf_len);
                memcpy(handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(int)*3) + cert_buf_len, pubkey_buf, pubkey_buf_len);
                memcpy(handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(int)*3) + cert_buf_len + pubkey_buf_len, signature, signature_len);

                delete [] cert_buf; cert_buf = NULL;
                delete [] pubkey_buf; pubkey_buf = NULL;
                delete [] signature; signature = NULL;

                if(send_data(fd, handshake_msg, handshake_msg_len) == 0){
                    // manage error
                }
                
                delete [] handshake_msg;
                break;
            }
            case HANDSHAKE_PH3:{

                /* ------------------------------------------------------------------------------------ */
                /* Third phase: CLIENT EXCHANGE.                                                        */
                /* Client validates Server certificate and received signature                           */
                /* Compute public EECDH and a signature with client's private RSA key as:               */
                /*                  Sign(RSAprv, EECHD || Client.Nonce || Server.Nonce)                 */
                /* Finally it sends < EECDH, Server.Nonce, Signature >                                  */
                /* ------------------------------------------------------------------------------------ */

                // CONTROLLARE SE IL SERVER NONCE CORRISPONDE
                unsigned char* received_srv_nonce;
                NEW(received_srv_nonce, new unsigned char[NONCE_LEN], "received srv nonce");
                memcpy(received_srv_nonce, handshake_msg + sizeof(command_t), NONCE_LEN);

                int clt_pubkey_len, signature_len;
                memcpy(&clt_pubkey_len, handshake_msg + sizeof(command_t) + NONCE_LEN, sizeof(int));
                memcpy(&signature_len, handshake_msg + sizeof(command_t) + NONCE_LEN + sizeof(int), sizeof(int));
                
                unsigned char* clt_pubkey_buf; NEW(clt_pubkey_buf, new unsigned char[clt_pubkey_len], "server public key");
                memcpy(clt_pubkey_buf, handshake_msg + sizeof(command_t) + NONCE_LEN + (sizeof(int)*2), clt_pubkey_len);

                // printf("Client DH Pubkey: \n");
                // BIO_dump_fp (stdout, (const char *)clt_pubkey_buf, clt_pubkey_len);

                EVP_PKEY* clt_dh_pubkey = deserialize_pubkey(clt_pubkey_buf, clt_pubkey_len);
                if(!clt_dh_pubkey){
                    cout << "ERROR: Deserialization of public key" << endl;
                    delete [] clt_pubkey_buf;
                    error_occurred = true; break;
                }

                // Read signature
                NEW(signature, new unsigned char[signature_len], "server signature");
                memcpy(signature, handshake_msg + sizeof(command_t) + NONCE_LEN + (sizeof(int)*2) + clt_pubkey_len, signature_len);
                //err = readn(fd, signature, signature_len);
                //if(err <= 0){
                //    delete [] clt_pubkey_buf;
                //    delete [] signature;
                //    EVP_PKEY_free(clt_dh_pubkey); 
                //    error_occurred = true; break;
                //}

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
                delete [] handshake_msg;

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
                    //msg_type = HANDSHAKE_ERR;
                    //string error_msg = "Signature verification FAILED";
                    //int error_size = error_msg.size()+1;
                    //writen(fd, &msg_type, sizeof(command_t));
                    //writen(fd, &error_size, sizeof(int));
                    //writen(fd, (void*)error_msg.c_str(), error_size);
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
                
                int reason_len;
                memcpy(&reason_len, handshake_msg + sizeof(command_t), sizeof(int));

                char *reason; NEW(reason, new char[reason_len+1], "reason msg");
                memcpy(reason, handshake_msg + sizeof(command_t)+ sizeof(int), reason_len);
                
                reason[size] = '\0';
                cout << reason << endl;
                delete [] reason;
                delete [] handshake_msg;
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

unsigned char* update_key(int fd, unsigned char* key, int* seq_number){
    cout << *seq_number << endl;
    // Reading update key request
    command_t msg_type = read_authenticated_msg(fd, key, seq_number);
    if(msg_type != UPDATE_KEY_REQ){
        send_authenticated_msg(fd, key, OP_FAIL, seq_number);
        return NULL;
    }

    int err = send_authenticated_msg(fd, key, UPDATE_KEY_ACK, seq_number);
    if(err == 0){
        return NULL;
    }

    // Now we can start the new exchange
    int msg_len = 0;
    unsigned char* update_key_msg = NULL;
    unsigned char* pubkey_buf = NULL;
    unsigned char* clt_pubkey_buf = NULL;
    int clt_pubkey_len;
    EVP_PKEY* clt_dh_pubkey = NULL;
    EVP_PKEY* my_dhkey = NULL;
    
    // Generate ephimeral DH
    my_dhkey = generate_pubkey();
    if(!my_dhkey){
        cout << "ERRORE mydh key" << endl;
    }
    int pubkey_buf_len = serialize_pubkey(fd, my_dhkey, &pubkey_buf);
    if (pubkey_buf_len == 0){
        cout << "ERRORE pubkey buf len" << endl;
    }

    msg_type = read_data_message(fd, key, &clt_pubkey_buf, &clt_pubkey_len, seq_number);
    if(msg_type == OP_FAIL){
    }
    clt_dh_pubkey = deserialize_pubkey(clt_pubkey_buf, clt_pubkey_len);
    if(!clt_dh_pubkey){
        cout << "Errore dh srv" << endl;
    }

    err = send_data_message(fd, key, UPDATE_KEY_REQ, pubkey_buf, pubkey_buf_len, seq_number);
    if (err == 0){
        //check errors
    }

    delete [] clt_pubkey_buf;
    delete [] pubkey_buf;

    // Derive new shared secret
    unsigned char* skey;
    int skeylen = derive_shared_secret(my_dhkey, clt_dh_pubkey, &skey);
    if (skeylen == 0){
        cout << "ERRORE skeylen" << endl;
    }

    printf("Here it is the shared secret pre-hash: \n");
    BIO_dump_fp (stdout, (const char *)skey, skeylen);
    // Using SHA-256 to extract a safe key!
    unsigned char* digest; 
    NEW(digest, new unsigned char[EVP_MD_size(EVP_sha256())], "digest for secret key");
    int digestlen = hash_secret(digest, skey, skeylen);
    if (digestlen == 0){
        cout << "ERRORE digestlen1" << endl;
        free_crypto(skey, skeylen);
    }

    int keylen = EVP_CIPHER_key_length(EVP_aes_128_gcm());

    unsigned char* shared_key = NULL;
    NEW(shared_key, new unsigned char[keylen], "shared secret");
    memcpy(shared_key, digest, keylen);
    printf("Here it is the shared secret: \n");
    BIO_dump_fp (stdout, (const char *)shared_key, keylen);
    free_crypto(digest, digestlen);
    free_crypto(skey, skeylen);
    *seq_number = 0;
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
    command_t msg_type = (files.size()>0) ? LIST_RSP : LIST_DONE;
    // Send list done
    err = send_authenticated_msg(fd, key, msg_type, seq_number);
    if(err == 0){
        cout << "Fail to send list done command" << endl;
        return ;
    }
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

void delete_file(int fd, string username, unsigned char *key, int* seq_number, string data){
    // NEED to SANITIZE DATA
    string path = SERVER_STORAGE + username;
    // canonicalize path
    command_t msg_type = NO_SUCH_FILE;
    vector<string> files;
    DIR *dir;
    struct dirent *diread;
    int err, nfiles = 0;
    if ((dir = opendir(path.c_str())) != NULL){
        while ((diread = readdir(dir)) != NULL){
            if (strncmp(diread->d_name, ".", 1) != 0 && 
                strncmp(diread->d_name, "..", 2) != 0 && data.compare(diread->d_name) == 0){
                msg_type = DELETE_CONFIRM;
                break;
            }
        }
        closedir(dir);
    }
    else{
        perror("opendir");
        return;
    }

    //auto iter = files.begin();
    //while(iter != files.end()){
    //    if(data.compare(*iter) == 0){
    //        msg_type = DELETE_CONFIRM;
    //        break;
    //    }
    //    iter++;
    //}

    // Send request to confirm
    err = send_authenticated_msg(fd, key, msg_type, seq_number);
    if(err == 0){
        cout << "Fail to send delete command" << endl;
        return;
    }
    if (msg_type == NO_SUCH_FILE)
        //file not found in server storage
        return;

    // Read client's reply
    msg_type = read_authenticated_msg(fd, key, seq_number);
    if(msg_type != DELETE_OK && msg_type != DELETE_ABORT){
        // SHOULD SEND SOME ERROR?
        cout << "Client's reply not recognized" << endl;
        return;
    }

    if(msg_type == DELETE_ABORT){
        cout << data <<": deletion cancelled" << endl;
        return;
    }

    // here we can delete file
    string file_path = path + "/" + data; // canonicalization?
    if (remove(file_path.c_str()) != 0){
        send_authenticated_msg(fd, key, OP_FAIL, seq_number);
    }   
    else send_authenticated_msg(fd, key, DELETE_OK, seq_number);
    return;
}

void upload_file(int fd, string username, unsigned char *key, int* seq_number, string data){
    // NEED to SANITIZE DATA
    string filepath = SERVER_STORAGE + username + "/" + data;
    int pt_len = 0;
    unsigned char* plaintext;
    // canonicalize path
    command_t msg_type = UPLOAD_REQ;
    FILE* file = fopen(filepath.c_str(), "w+");
    if(!file){
        cout << "Cannot create file" << endl;
        return;
    }
    while(msg_type != UPLOAD_END){
        msg_type = read_data_message(fd, key, &plaintext, &pt_len, seq_number);
        // if errore remove file -> remove(filename.c_str());
        fwrite(plaintext, 1, pt_len, file);
        delete [] plaintext;
    }

    // Upload finished
    int err = send_authenticated_msg(fd, key, UPLOAD_DONE, seq_number);
    if(err == 0){
        cout << "Fail to send upload done command" << endl;
        return;
    }
    // ###############################

    //controlla che la stringa ricevuta sia valida
    //if(!check_string(std::string((char*)plaintext))){
    //    id = 8; //ID di errore 
    //    msg = std::string("Filename non valido");
    //    msg.resize(SIZE_FILENAME);
    //}
    //if(num_packets > UINT32_MAX/MAX_PAYLOAD_SIZE){
    //    std::cout<<"Tentativo di inviare un file più grande di 4GB\n";
    //    return;
    //}
    fclose(file);
    return;
}

void download_file(int fd, string username, unsigned char *key, int* seq_number, string filename){
    //controllo la validità del nome
    //if(!check_string(filename))
    //    return;

    uint64_t file_len;
    uint32_t fragments = 0;
    //check if file exist locally
    string filepath = SERVER_STORAGE + username + "/" + filename;
    // forse va aperto in rb?
    FILE* file = fopen(filepath.c_str(),"r");
    if(!file){
        cout << "File do not exists" << endl;
        send_authenticated_msg(fd, key, NO_SUCH_FILE, seq_number);
        return;
    }
    else{
        fseek(file,0,SEEK_END);
        // taking file len
        file_len = (ftell(file) > UINT32_MAX)? 0: ftell(file);
        if(!file_len && ftell(file)){
            cout << "File too big or empty" << endl;
            send_authenticated_msg(fd, key, NOT_VALID_FILE, seq_number);
            fclose(file);
            return;
        }
    }
   
    fseek(file, 0, SEEK_SET);
    // Checks ok, send the file to client.
    // We need to split the file to smaller fragment of fixed lenght
    fragments = file_len/MAX_FRAGMENT_SIZE + (file_len % MAX_FRAGMENT_SIZE != 0);
    int err = send_authenticated_msg(fd, key, DOWNLOAD_OK, seq_number);
    if(err == 0){
        cout << "Fail to send upload done command" << endl;
        return;
    }
    const auto progress_level = static_cast<int>(fragments*0.01);
    // Send the file
    cout << "Sending " << '"'<< filename <<'"' << " with " << fragments << " frags" << endl;
    uint32_t data_len;
    unsigned char* data;
    command_t msg_type = DOWNLOAD_FRGM; 
    int progress;
    for (int i = 0; i< fragments; i++){
        progress = static_cast<int>(i/progress_level);
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
            if(progress <= 100)
                cout << "\r [" << std::setw(4) << progress << "%] " << "Sending..." << std::flush;
        }
        
        int err = send_data_message(fd, key, msg_type, data, data_len, seq_number);
        if (err == 0){
            cout << "Failed to send data during download" << endl;

        }

        delete [] data;
        //cout << i << endl;
    }
    cout << endl;
    fclose(file);
    
    cout << "File correctly sent!" << endl;
}

void rename_file(int fd, string username, unsigned char *key, int* seq_number, string data){
    // NEED to SANITIZE DATA
    string path = SERVER_STORAGE + username;
    // canonicalize path
    command_t msg_type = NO_SUCH_FILE;
    DIR *dir;
    struct dirent *diread;
    int err, nfiles = 0;

    int index = data.find(";");
    string old_file, new_filename;
    old_file = data.substr(0, index);
    new_filename = data.substr(index+1);

    cout << old_file << "-" << new_filename << endl;
    // Check validity of old e new name
    if ((dir = opendir(path.c_str())) != NULL){
        while ((diread = readdir(dir)) != NULL){
            if (strncmp(diread->d_name, ".", 1) != 0 && 
                strncmp(diread->d_name, "..", 2) != 0 && old_file.compare(diread->d_name) == 0){
                msg_type = RENAME_OK;
                break;
            }
        }
        closedir(dir);
    }
    else{
        perror("opendir");
        return;
    }

    if (msg_type == RENAME_OK){
        //File found, renaming it
        string old_path = path + "/" + old_file;
        string new_path = path + "/" + new_filename;
        err = rename(old_path.c_str(), new_path.c_str());
        if (err != 0){
            msg_type = OP_FAIL;
            cout << "Fail to rename file "<< old_file << endl;
        }
        else cout << "Successfully renamed file" << endl;
    }
    else cout << "No such file in user storage" << endl;

    // Send result to client
    err = send_authenticated_msg(fd, key, msg_type, seq_number);
    if(err == 0){
        cout << "Fail to send result to client" << endl;
        return;
    }

    return;
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