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
#include <map>

#define PORT 4333
#define USER_PATH "./"
#define STORAGE_PATH "/storage/"
#define CA_CERT_PATH "/FoundationsOfCybersecurity_cert.pem"
#define CA_CRL_PATH "/FoundationsOfCybersecurity_crl.pem"
#define MAX_FRAGMENT_SIZE 1024

int list_command(int fd, unsigned char* key, int* seq_number);
void delete_command(int fd, unsigned char* key, int* seq_number);
void rename_command(int fd, unsigned char* key, int* seq_number);
int logout(int fd, unsigned char* key, int* seq_number);
void canonicalize(string s1);
bool check_strings(string s1);

void show_help_msg();

unsigned char* handshake(int fd, string username);

int main(){
    show_help_msg();
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

    // Possible commands
    map<string,int> commands;
    commands.insert(pair<string,int>("list",LIST));
    commands.insert(pair<string,int>("upload", UPLOAD));
    commands.insert(pair<string,int>("download",DOWNLOAD));
    commands.insert(pair<string,int>("rename",RENAME));
    commands.insert(pair<string,int>("delete",DELETE));
    commands.insert(pair<string,int>("logout",LOGOUT));
    commands.insert(pair<string,int>("help",HELP));

    string command, username;
    cout << "Enter your username: ";
    getline(cin, username);
    if(!cin) { cerr << "Error during input\n"; exit(1); }
    // SANITAZE USERNAME
    unsigned char* key = handshake(client_skt, username);
    if (!key) {
        close(client_skt);
        return 0;
    }
    int keylen = EVP_CIPHER_key_length(EVP_aes_128_gcm());
    int seq_number = 0;

    cout << "\nHandshake successful. Connected!" << endl;

    int logged_in = 1;
    while(logged_in){
        cout << "Enter command: ";
        getline(cin, command);
        if(!cin) { cerr << "Error during input\n"; exit(1); }
        // SANITIZE COMMAND
        // substite \n with \0
        switch(commands[command]) {
            case LIST:{
                cout << "List command inserted" << endl;
                int err = list_command(client_skt, key, &seq_number);
                // check errors
                break;
            }
            case LOGOUT:{
                // int err = send_authenticated_msg(client_skt, key, LOGOUT, &seq_number);
                int err = send_message(client_skt, key, LOGOUT,"", &seq_number);
                if(err==0){
                    cout << "Cannot send logout message, terminating" << endl;
                }
                logged_in = 0;
                break;
            }
            case DELETE:{
                cout << "Delete command inserted" << endl;
                delete_command(client_skt, key, &seq_number);
                // check errors
                break;
            }
            case RENAME:{
                cout << "Rename command inserted" << endl;
                rename_command(client_skt, key, &seq_number);
                break;
            }
            case HELP:{
                show_help_msg();
                break;
            }
            default:
                cout << "Command not recognized" << endl;
                break;
                // code block
        }
    }
    free_crypto(key, keylen);
    close(client_skt);
    return 0;
}

unsigned char* handshake(int fd, string username){

    int err, size, handshake_msg_len;
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
    printf("Client nonce: \n");
    BIO_dump_fp (stdout, (const char *)clt_nonce, NONCE_LEN);

    int username_size = username.size();
    cout << "Sent username len: " << username_size << endl;
    msg_type = HANDSHAKE_PH1;
    handshake_msg_len = sizeof(command_t) + NONCE_LEN + sizeof(int) + username_size; 
    NEW(handshake_msg, new unsigned char[handshake_msg_len], "phase1: handshake msg");
    memcpy(handshake_msg, &msg_type, sizeof(command_t));
    memcpy(handshake_msg + sizeof(command_t), clt_nonce, NONCE_LEN);
    memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN, &username_size, sizeof(int));
    memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN + sizeof(int), username.c_str(), username_size);

    err = send_data(fd, handshake_msg, handshake_msg_len);
    delete [] handshake_msg;
    if(err == 0){
        delete [] clt_nonce;
        return NULL;
    }
    
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
        switch(msg_type) {
            case HANDSHAKE_PH2:{

                /* ------------------------------------------------------------------------------------ */
                /* SECOND PHASE: server exchange                                                        */
                /* Client receives srv certificate, ephimeral srv pub key, signature                    */
                /* Client retrieve public key from srv certificate, verify the signature                */
                /* ------------------------------------------------------------------------------------ */

                NEW(srv_nonce, new unsigned char[NONCE_LEN], "server nonce");
                memcpy(srv_nonce, handshake_msg + sizeof(command_t), NONCE_LEN);

                printf("Server nonce: \n");
                BIO_dump_fp (stdout, (const char *)srv_nonce, NONCE_LEN);

                unsigned char* received_clt_nonce;
                NEW(received_clt_nonce, new unsigned char[NONCE_LEN], "received clt nonce");

                // Get Client.Nonce for freshness
                memcpy(received_clt_nonce, handshake_msg + sizeof(command_t) + NONCE_LEN, NONCE_LEN);
                // need to check for received client nonce COMPARE THEM

                // Get server certificate
                int srv_cert_len, srv_pubkey_len, signature_len;
                memcpy(&srv_cert_len, handshake_msg + sizeof(command_t) + (NONCE_LEN*2), sizeof(int));
                memcpy(&srv_pubkey_len, handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + sizeof(int), sizeof(int));
                memcpy(&signature_len, handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(int)*2), sizeof(int));

                NEW(srv_cert_buf, new unsigned char[srv_cert_len], "server certificate");
                memcpy(srv_cert_buf, handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(int)*3), srv_cert_len);

                NEW(srv_pubkey_buf, new unsigned char[srv_pubkey_len], "server public key");
                memcpy(srv_pubkey_buf, handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(int)*3) + srv_cert_len, srv_pubkey_len);

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

                unsigned char* signature; NEW(signature, new unsigned char[signature_len], "server signature");
                memcpy(signature, handshake_msg + sizeof(command_t) + (NONCE_LEN*2) + (sizeof(int)*3) + srv_cert_len + srv_pubkey_len, signature_len);
                
                delete [] handshake_msg;

                printf("Server signature: \n");
                BIO_dump_fp (stdout, (const char *)signature, signature_len);

                // Load the CA's certificate
                string cacert_file_name = USER_PATH + username + CA_CERT_PATH;
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
                string crl_file_name = USER_PATH + username + CA_CRL_PATH;
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
                    //msg_type = HANDSHAKE_ERR;
                    //string error_msg = "Certificate verification FAILED";
                    //int error_size = error_msg.size()+1;
                    //writen(fd, &msg_type, sizeof(command_t));
                    //writen(fd, &error_size, sizeof(int));
                    //writen(fd, (void*)error_msg.c_str(), error_size);
                    break;
                }

                cout << "Certificate verification: OK" << endl;
                // We need to verify signature
                int to_verify_len = srv_pubkey_len + (NONCE_LEN*2);
                unsigned char* to_verify; NEW(to_verify, new unsigned char[to_verify_len], "to_verify buffer");
                memcpy(to_verify, srv_pubkey_buf, srv_pubkey_len);
                memcpy(to_verify + srv_pubkey_len, clt_nonce, NONCE_LEN);
                memcpy(to_verify + srv_pubkey_len + NONCE_LEN, srv_nonce, NONCE_LEN);

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
                string path = USER_PATH + username +"/" + username + "_prvkey.pem";
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
                handshake_msg_len = sizeof(command_t) + NONCE_LEN + (sizeof(int)*2) + pubkey_buf_len + signature_len;
                NEW(handshake_msg, new unsigned char[handshake_msg_len], "phase3: handshake msg");
                memcpy(handshake_msg, &msg_type, sizeof(command_t));
                memcpy(handshake_msg + sizeof(command_t), srv_nonce, NONCE_LEN);
                memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN, &pubkey_buf_len, sizeof(int));
                memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN + sizeof(int), &signature_len, sizeof(int));
                memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN + (sizeof(int)*2), pubkey_buf, pubkey_buf_len);
                memcpy(handshake_msg + sizeof(command_t) + NONCE_LEN + (sizeof(int)*2) + pubkey_buf_len, signature, signature_len);

                err = send_data(fd, handshake_msg, handshake_msg_len);
                if (err == 0){
                    // manage errors
                }

                delete [] handshake_msg;                
                delete [] pubkey_buf;
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

int list_command(int fd, unsigned char* key, int* seq_number){
    int nmessages;
    vector<string> files;

    int err = send_message(fd, key, LIST_REQ,"", seq_number);
    if(err == 0){
        cout << "Fail to send list command" << endl;
        return 0;
    }

    // Sending request for file listing
    //int err = send_authenticated_msg(fd, key, LIST_REQ, seq_number);
    //if(err == 0){
    //    cout << "Fail to send list command" << endl;
    //    return 0;
    //}
    command_t msg_type = read_authenticated_msg(fd, key, seq_number);
    string plaintext = "";
    while(msg_type != LIST_DONE){
        // Get server response with the number of message to read
        msg_type = read_message(fd, key, plaintext, seq_number);
        if(msg_type != LIST_RSP && msg_type != LIST_DONE){
            // manage error
        }
        files.push_back(plaintext);
    }
    if(msg_type != LIST_RSP && msg_type != LIST_DONE){
        // manage error
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
    return 1;
}

void delete_command(int fd, unsigned char* key, int* seq_number){
    cout << "Enter the filename to delete: ";
    string file;
    command_t msg_type;
    getline(cin, file);
    if(!cin) { cerr << "Error during input\n"; exit(1); }

    // Sanitize filename
    int err = send_message(fd, key, DELETE_REQ, file, seq_number);
    if (err == 0){
        // Check errors
    }

    msg_type = read_authenticated_msg(fd, key, seq_number);
    //cout << msg_type << endl;
    if(msg_type != DELETE_CONFIRM && msg_type != NO_SUCH_FILE){
        cout << "Something went wrong in server... try later" << endl;
        return;
    }
    if(msg_type == NO_SUCH_FILE){
        cout << "Cannot delete file because it doesn't exist in your storage" << endl;
        return;
    }

    cout << "Are you sure you want to delete " << file << "? [y/n]" << endl;
    getline(cin , file);
    if(!cin) { cerr << "Error during input\n"; exit(1); }
    while((file.compare("y")!=0) && (file.compare("n")!=0)){
        cout << "Just type y or n to complete the request"<<endl;
        getline(cin, file);
        if(!cin) { cerr << "Error during input\n"; exit(1); }
    }

    if (file.compare("n") == 0){
        err = send_authenticated_msg(fd, key, DELETE_ABORT, seq_number);
        if(err == 0)
            cout << "Fail to send delete command" << endl;
        else cout << "Aborted. No file deleted" << endl;
        return;
    }

    err = send_authenticated_msg(fd, key, DELETE_OK, seq_number);
    if(err == 0){
        cout << "Fail to send delete command" << endl;
        return;
    }

    msg_type = read_authenticated_msg(fd, key, seq_number);
    if(msg_type == DELETE_OK)
        cout << "File successfully deleted" << endl;
    else 
        cout << "Cannot delete file on the server" << endl;
    return;
}

void upload_command(int fd, unsigned char* key, int* seq_number){
    //chiedo all'utente il nome del file su cui desidera fare upload 
    cout<<"Enter the filename to upload: ";
    string filename;
    getline(cin, filename);

    //ne controllo la validità
    //if(!check_string(filename))
    //    return;

    uint8_t id;
    uint64_t file_len;
    uint32_t fragments = 0;

    //check if file exist locally
    string filepath = "./alice/storage/" + filename;
    FILE* file = fopen(filepath.c_str(),"r");
    if(!file){
        cout << "File do not exists" << endl;
        return;
    }
    else{
        fseek(file,0,SEEK_END);
        // taking file len
        file_len = (ftell(file) > UINT32_MAX)? 0: ftell(file);
        // is the check for 4gb correct?
        if(!file_len && ftell(file)){
            cout << "File too big or empty" << endl;
            fclose(file);
            return;
        }
    }
   
    fseek(file, 0, SEEK_SET);
    // Checks ok, send the request to the server
    int err = send_message(fd, key, UPLOAD_REQ, filename, seq_number);
    if (err == 0){
        // Check errors
        fclose(file);
    }
    //filename.reserve(SIZE_FILENAME);
    //filename.resize(SIZE_FILENAME);

    // Now we need to split the file to smaller fragment of fixed lenght
    fragments = file_len/MAX_FRAGMENT_SIZE + (file_len % MAX_FRAGMENT_SIZE != 0);

    // Upload the file
    cout << "Uploading " << '"'<<filename<<'"' << " with " << fragments << " frags" << endl;
    if(!file) {
        cout<<"Errore nell'apertura del file in lettura" << endl;
        return;
    }
    unsigned char* data;
    uint32_t data_len;
    command_t msg_type = UPLOAD_FRGM; 
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
        }
        else {
            NEW(data, new unsigned char[MAX_FRAGMENT_SIZE], "Allocating data file");
            fread(data,1,MAX_FRAGMENT_SIZE,file);
            data_len = MAX_FRAGMENT_SIZE;
        }
        
        int err = send_data_message(fd, key, msg_type, data, data_len, seq_number);
        if (err == 0){
            // check errors
        }
        delete [] data;
    }
    fclose(file);
    
    command_t msg_type = read_authenticated_msg(fd, key, seq_number);
    //cout << msg_type << endl;
    if(msg_type == OP_FAIL){
        cout << "Something went wrong in server... try later" << endl;
        return;
    } else if (msg_type != UPLOAD_DONE){
        cout << "Operation failed" << endl;
    } else cout << "File uploaded!" << endl;
    return;
}

void rename_command(int fd, unsigned char* key, int* seq_number){
    cout << "Enter file to rename: ";
    string old_file;
    getline(cin, old_file);
    if(!cin) { cerr << "Error during input\n"; exit(1); }
    // SANITIZE
    cout << "Enter new file name: ";
    string new_filename;
    getline(cin, new_filename);
    if(!cin) { cerr << "Error during input\n"; exit(1); }
    // SANITIZE

    // sending request to server
    int err = send_message(fd, key, RENAME_REQ, old_file + ";" + new_filename , seq_number);
    if (err == 0){
        // Check errors
    }

    command_t msg_type = read_authenticated_msg(fd, key, seq_number);
    //cout << msg_type << endl;
    if(msg_type != RENAME_OK && msg_type != NO_SUCH_FILE){
        cout << "Something went wrong in server... try later" << endl;
        return;
    }
    if(msg_type == NO_SUCH_FILE){
        cout << "Cannot rename file because it doesn't exist in your storage" << endl;
    } else if (msg_type == OP_FAIL){
        cout << "Operation failed" << endl;
    } else cout << "File renamed!" << endl;

    return;
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

void show_help_msg(){


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
    "╋╋╋╋╋╋╋╋╋╋╋╋╋┗━━┻━┻┻━━┻┛┗┻━┛ \n\n" << endl;

    cout << "Cloud Storage Client\n"
    "Command list\n"
    "\t- list shows available files in your storage\n"
    "\t- rename request the file to be renamed and the new name\n"
    "\t- delete request the file to be deleted\n"
    "\t- logout gracefully exit the application\n" << endl;
}   
