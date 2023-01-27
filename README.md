# Cloud Storage
## A secure remote storage

Cloud Storage is an application where each user has a dedicated storage space on the server that only they can access. Users can upload, download, rename and delete data to/from the cloud storage in a secure manner.

### Quick start

Compile the application with:

`$ ./compile.sh`

By default, Server is listening on all interfaces on port 4333. To start the Server run:

```bash
$ cd Server/
$ ./server
```

By default, Client connects to localhost on port 4333. To start the Client, in a new terminal run:

```bash
$ cd Client/
$ ./client
```

**Note:** Files can only be uploaded if they are in *\<user\>/storage/*

### Client configuration

Client application comes preconfigured with three default users to test the application: alice, bob and charlie. To add more users make sure to fulfill these requirements:
1. Each user needs to have a *storage* folder used to manage uploaded/downloaded files. **If you want to upload a file, it needs to be located in this folder.**
2. Long-term RSA private and public key have to be located in specific user folder.

Finally CA certificate and CRL must be placed in the Client folder.

### Server configuration

Server is configured through a configuration file under the *config* folder to preregister users in the application by specifing their name and path to public key.
Server certificate signed by CA must be placed in the Server folder.
