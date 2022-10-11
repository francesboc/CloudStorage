#include <iostream>
#include <stdio.h>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../Common/utils.h"
#include "../Common/crypto.h"
#include <fstream>
#include <map>

#define PORT 4333
#define USER_PATH "./Alice/"

void list_command(int fd, unsigned char* key);
void logout(int fd, unsigned char* key);
void canonicalize(string s1);
bool check_strings(string s1);

unsigned char* handshake(int fd, string username);

int main(){

    int client_skt;
    struct sockaddr_in address;

    memset(&address,0,sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) <= 0) {
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

    // TO REMOVE
    //unsigned char key[] = "1234567890123456";
    //unsigned char iv[]  = "123456780912";

    // Possible commands
    map<string,int> commands;
    commands.insert(pair<string,int>("list",LIST));
    commands.insert(pair<string,int>("upload", UPLOAD));
    commands.insert(pair<string,int>("download",DOWNLOAD));
    commands.insert(pair<string,int>("rename",RENAME));
    commands.insert(pair<string,int>("delete",DELETE));
    commands.insert(pair<string,int>("logout",LOGOUT));

    string command, username;
    cout << "Enter your username: ";
    getline(cin, username);
    if(!cin) { cerr << "Error during input\n"; exit(1); }
    //writen(client_skt, (char*)username.c_str(), username.size());
    unsigned char* key = handshake(client_skt, username);
    if (!key) {
        close(client_skt);
        return 0;
    }
    cout << "Connected!" << endl;

    int logged_in = 1;
    while(logged_in){
        cout << "Enter command: ";
        getline(cin, command);
        if(!cin) { cerr << "Error during input\n"; exit(1); }

        switch(commands[command]) {
            case LIST:{
                // code block
                cout << "List command inserted" << endl;
                list_command(client_skt, key);
                break;
            }
            case LOGOUT:{
                logout(client_skt,key);
                logged_in = 0;
                break;
            }
            default:
                cout << "Command not recognized" << endl;
                break;
                // code block
        }
    }
    close(client_skt);
    return 0;
}

unsigned char* handshake(int fd, string username){

    int err, size;
    unsigned char* srv_nonce = NULL; 
    unsigned char* shared_key = NULL;
    unsigned char* srv_cert_buf = NULL;
    unsigned char* srv_pubkey_buf = NULL;
    X509* srv_cert = NULL;
    EVP_PKEY* srv_dh_pubkey = NULL;
    EVP_PKEY *my_dhkey = NULL;

    /* ------------------------------------------------------------------------------------ */
    /* FIRST PHASE: Client sends nonce and username                                         */
    /* ------------------------------------------------------------------------------------ */

    command_t hs_req = HANDSHAKE_REQ;
    err = writen(fd, &hs_req, sizeof(command_t));
    if (err <= 0) return NULL;

    unsigned char* clt_nonce; NEW(clt_nonce, new unsigned char[NONCE_LEN], "client nonce");
    generate_random(clt_nonce, NONCE_LEN);

    err = writen(fd, clt_nonce, NONCE_LEN);
    if (err <= 0){
        delete [] clt_nonce;
        return NULL;
    }

    err = writen(fd, (void*)username.c_str(), USRNM_LEN);
    if (err <= 0){
        delete [] clt_nonce;
        return NULL;
    }

    command_t msg_type;
    bool handshake_finished = false;
    bool error_occurred = false;
    
    while(!handshake_finished && !error_occurred){
        err = readn(fd, &msg_type, sizeof(command_t));
        if(err <= 0) { error_occurred = true; break; }
        switch(msg_type) {
            case HANDSHAKE_PH1:{

                /* ------------------------------------------------------------------------------------ */
                /* FIRST PHASE (continue): Client receives server nonce                                 */
                /* ------------------------------------------------------------------------------------ */

                NEW(srv_nonce, new unsigned char[NONCE_LEN], "server nonce");
                err = readn(fd, srv_nonce, NONCE_LEN);
                if (err <= 0) { error_occurred = true; break; }

                printf("------------------------ FASE 1 ------------------------\n");
                printf("Client nonce: \n");
                BIO_dump_fp (stdout, (const char *)clt_nonce, NONCE_LEN);
                printf("Server nonce: \n");
                BIO_dump_fp (stdout, (const char *)srv_nonce, NONCE_LEN);
                break;
            }
            case HANDSHAKE_PH2:{
                
                /* ------------------------------------------------------------------------------------ */
                /* SECOND PHASE: server exchange                                                        */
                /* Client receives srv certificate, ephimeral srv pub key, signature                    */
                /* Client retrieve public key from srv certificate, verify the signature                */
                /* ------------------------------------------------------------------------------------ */

                printf("------------------------ FASE 2 ------------------------\n");
                
                int srv_cert_len;
                err = readn(fd, &srv_cert_len, sizeof(int));
                if (err <= 0) { error_occurred = true; break; }

                NEW(srv_cert_buf, new unsigned char[srv_cert_len], "server certificate");
                err = readn(fd, srv_cert_buf, srv_cert_len);
                if (err <= 0) { error_occurred = true; break; }

                //printf("Server certificate: \n");
                //BIO_dump_fp (stdout, (const char *)srv_cert_buf, srv_cert_len);

                int srv_pubkey_len;
                err = readn(fd, &srv_pubkey_len, sizeof(int));
                if (err <= 0) { error_occurred = true; break; }

                NEW(srv_pubkey_buf, new unsigned char[srv_pubkey_len], "server public key");
                err = readn(fd, srv_pubkey_buf, srv_pubkey_len);
                if (err <= 0) { error_occurred = true; break; }

                //printf("Server DH Pubkey: \n");
                //BIO_dump_fp (stdout, (const char *)srv_pubkey_buf, srv_pubkey_len);

                srv_cert = deserialize_certificate(srv_cert_buf, srv_cert_len);
                if(!srv_cert){ 
                    cout << "Errore srv cert" << endl;
                    error_occurred = true; break;
                }

                srv_dh_pubkey = deserialize_pubkey(srv_pubkey_buf, srv_pubkey_len);
                if(!srv_dh_pubkey){
                    cout << "Errore dh srv" << endl;
                    error_occurred = true; break;
                }

                // Read signature
                int signature_len;
                err = readn(fd, &signature_len, sizeof(int));
                if (err <= 0) { error_occurred = true; break; }
                unsigned char* signature; NEW(signature, new unsigned char[signature_len], "server signature");
                err = readn(fd, signature, signature_len);
                if (err <= 0) { 
                    delete [] signature;
                    error_occurred = true; break; 
                }

                //printf("Server signature: \n");
                //BIO_dump_fp (stdout, (const char *)signature, signature_len);

                // Load the CA's certificate
                string cacert_file_name= USER_PATH + (string)"FoundationsOfCybersecurity_cert.pem";
                FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
                if(!cacert_file){ 
                    cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n";
                    delete [] signature;
                    error_occurred = true; break;
                }
                X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
                fclose(cacert_file);
                if(!cacert){ 
                    cerr << "Error: PEM_read_X509 returned NULL\n";
                    delete [] signature;
                    error_occurred = true; break;
                }
                
                // load the CRL:
                string crl_file_name= USER_PATH + (string)"FoundationsOfCybersecurity_crl.pem";
                FILE* crl_file = fopen(crl_file_name.c_str(), "r");
                if(!crl_file){ 
                    cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n";
                    delete [] signature;
                    X509_free(cacert);
                    error_occurred = true; break; 
                }
                X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
                fclose(crl_file);
                if(!crl){ 
                    cerr << "Error: PEM_read_X509_CRL returned NULL\n";
                    delete [] signature;
                    X509_free(cacert);
                    error_occurred = true; break; 
                }

                int verify_cert = verify_certificate(cacert, crl, srv_cert);
                if(verify_cert == 0){
                    cout << "ERRORE Certificate verification FAILED" << endl;
                    delete [] signature;
                    error_occurred = true;
                    msg_type = HANDSHAKE_ERR;
                    string error_msg = "Certificate verification FAILED";
                    int error_size = error_msg.size()+1;
                    writen(fd, &msg_type, sizeof(command_t));
                    writen(fd, &error_size, sizeof(int));
                    writen(fd, (void*)error_msg.c_str(), error_size);
                    break;
                }

                cout << "Certificate verification: OK" << endl;
                // We need to verify signature
                int to_verify_len = srv_cert_len + srv_pubkey_len + (NONCE_LEN*2);
                unsigned char* to_verify; NEW(to_verify, new unsigned char[to_verify_len], "to_verify buffer");
                memcpy(to_verify, srv_cert_buf, srv_cert_len);
                memcpy(to_verify + srv_cert_len, srv_pubkey_buf, srv_pubkey_len);
                memcpy(to_verify + srv_cert_len + srv_pubkey_len, clt_nonce, NONCE_LEN);
                memcpy(to_verify + srv_cert_len + srv_pubkey_len + NONCE_LEN, srv_nonce, NONCE_LEN);

                //printf("Plain signature: \n");
                //BIO_dump_fp (stdout, (const char *)to_verify, to_verify_len);

                // extract pubic key from srv certificate
                EVP_PKEY* srv_cert_pubkey = X509_get_pubkey(srv_cert);
                if(!srv_cert_pubkey){
                    cout << "Errore srv_cert_pubkey" << endl;
                    delete [] signature;
                    delete [] to_verify;
                    error_occurred = true; break; 
                }

                int verify = verify_signature(srv_cert_pubkey, to_verify, to_verify_len, signature, signature_len);
                if(verify == 0){
                    delete [] signature;
                    delete [] to_verify;
                    EVP_PKEY_free(srv_cert_pubkey);
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
                delete [] srv_cert_buf; srv_cert_buf = NULL;
                delete [] srv_pubkey_buf; srv_pubkey_buf = NULL;
                EVP_PKEY_free(srv_cert_pubkey);

                printf("------------------------ FASE 3 ------------------------\n");

                // Generate ephimeral DH
                my_dhkey = generate_pubkey();
                if(!my_dhkey){
                    cout << "ERRORE mydh key" << endl;
                    error_occurred = true; break; 
                }

                unsigned char* pubkey_buf;
                int pubkey_buf_len = serialize_pubkey(fd, my_dhkey, &pubkey_buf);
                if (pubkey_buf_len == 0){
                    cout << "ERRORE pubkey buf len" << endl;
                    error_occurred = true; break; 
                }

                //printf("Client DH Pubkey: \n");
                //BIO_dump_fp (stdout, (const char *)pubkey_buf, pubkey_buf_len);

                // First read client privkey
                string path = USER_PATH + (string)"alice_prvkey.pem";
                FILE* prvkey_file = fopen(path.c_str(), "r");
                if(!prvkey_file){ 
                    cout << "Errore prvkey file" << endl;
                    delete [] pubkey_buf;
                    error_occurred = true; break; 
                }
                EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
                fclose(prvkey_file);
                if(!prvkey){
                    cout << "Errore file" << endl;
                    delete [] pubkey_buf;
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
                    cout << "ERRORE signature_len" << endl;
                    delete [] pubkey_buf;
                    delete [] to_sign;
                    delete [] signature;
                    EVP_PKEY_free(prvkey);
                    error_occurred = true; break; 
                }

                delete [] to_sign;
                EVP_PKEY_free(prvkey);
                //printf("Client signature: \n");
                //BIO_dump_fp (stdout, (const char *)signature, signature_len);
            
                //printf("Plain signature: \n");
                //BIO_dump_fp (stdout, (const char *)to_sign, to_sign_len);

                msg_type = HANDSHAKE_PH3;
                err = writen(fd, &msg_type, sizeof(command_t));
                if (err <= 0){
                    delete [] pubkey_buf;
                    delete [] signature;
                    error_occurred = true; break; 
                }
                // Finally send: pubkey, signature
                err = writen(fd, &pubkey_buf_len, sizeof(int));
                if (err <= 0){
                    delete [] pubkey_buf;
                    delete [] signature;
                    error_occurred = true; break; 
                }
                err = writen(fd, pubkey_buf, pubkey_buf_len);
                if (err <= 0){
                    delete [] pubkey_buf;
                    delete [] signature;
                    error_occurred = true; break; 
                }
                delete [] pubkey_buf;

                err = writen(fd, &signature_len, sizeof(int));
                if (err <= 0){
                    delete [] signature;
                    error_occurred = true; break; 
                }
                err = writen(fd, signature, signature_len);
                if (err <= 0){
                    delete [] signature;
                    error_occurred = true; break; 
                }
                delete [] signature;

                printf("------------------------ FASE 4 ------------------------\n");

                // Derive the shared secret

                unsigned char* skey;
                int skeylen = derive_shared_secret(my_dhkey, srv_dh_pubkey, &skey);
                if (skeylen == 0){
                    cout << "ERRORE skeylen" << endl;
                    error_occurred = true; break; 
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
            case HANDSHAKE_ERR:{
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

// Da rivedere la struttura del messaggio inviato
void list_command(int fd, unsigned char* key){

    unsigned char msg[] = "list";
    int pt_len = sizeof(msg);

    send_message(fd, key, msg);

    unsigned char* response = NULL;
    // Get server response
    if (read_message(fd, key, &response) != CLR_FRAGMENT)
        cout << "FAIL retrieve list" << endl;
    
    cout << response << endl;
}

void logout(int fd, unsigned char* key){
    unsigned char msg[] = "logout";
    int pt_len = sizeof(msg);
    
    send_message(fd, key, msg);
}

void canonicalize(string s1){
    char* canon_str2 = realpath(s1.c_str(), NULL);
    if(!canon_str2) return;
    if(strncmp(canon_str2, "/home/", strlen("/home/")) != 0) { free(canon_str2); return; } // check that directory is "/home" (in some systems this should be: "/home/<username>")
    ifstream f(canon_str2, ios::in); // only files in the home directory or its subdirs should be opened here!
    free(canon_str2);
    if(!f) { cerr << "Cannot open " << s1 << endl; return; }
    string line;
    do{
        getline(f, line);
        cout << line << endl;
    }
    // THERE IS A TOCTOU problem
    while(!f.eof());
    f.close();
}

bool check_strings(string s1){
    if(s1.empty()) return false;
    static char ok_chars[] = "abcdefghijklmnopqrstuvwxyz"
                             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                             "1234567890-_.";
    if(s1.find_first_not_of(ok_chars) != string::npos) return false;
    if(s1[0] == '-' || s1[0] == '.' || s1[0] == '_') return false;
    return true;
}