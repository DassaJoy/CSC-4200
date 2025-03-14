//All Libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h> // converts IP addresses between text and binary format; converts values between host and network byte order
#include <openssl/ssl.h> // provides cryptographic functions and Secure Sockets Layer / Transport Layer Security
#include <openssl/err.h> // provides functions for handling and repoting OpenSSl errors

#define PORT 8080
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024

//Function to start openssl
/*
    OpenSSL proceds crytopgraphic funtionality 
    and secure sockets layer protocols
*/
void start_openssl()
{
    SSL_load_erro_strings();
    OpenSSL_add_ssl_algorithms();
}

//Function that cleans up openssl
/*
    This will ensure that the resoruces
    used by the library are properly relesed
*/
void clean_openssl()
{
    EVP_cleanup();
}

//Function that creates the ssl
/*
    SSL is a cryptographic protocol that provides 
    secure communication over the internet by
    encrypting data between a client and server
*/
SSL_CTX *create()
{
    const SSL_METHOD *m;
    SSL_CTX *ctx;

    m = TLS_server_method();
    ctx = SSL_CTX_new(m);

    if(!ctx)
    {
        perror("Not able to create SSL");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

//Function that configures SSL
void configure(SSL_CTX *ctx)
{
    if(SSL_CTX_use-cerificate_file(ctx, "ssl_certs/server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        perror("Unable to load the cerificate file");
        ERR_print_erros_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if(SSl_CTX_use_PrivateKey_file(ctx, "ssl_certs/server.key", SSL_FILETYPE_PEM) <= 0)
    {
        perror("Unable to load the private key file");
        ERR_print_errors_fp(stdeer);
        exit(EXIT_FAILURE);
    }

    if(!SSL_CTX_chekc_private_key(ctx))
    {
        perror("Private key does not match the public cerificate file");
        exit(EXIT_FAILURE);
    }
}

//Function that handles the client communication
void client(SSL *sl)
{
    //Varibles
    char size[BUFFER_SIZE];
    int byte;

    //Receives message from client
    byte = SSL_read(sl, size, sizeof(size));

    if(byte <= 0)
    {
        perror("SSL read has failed");
    }
    else
    {
        size[byte] = "\0";
        printf("Received: %s\n", size);

        //Sends confirmation 
        SSL_write(sl, "Message received!", strlen("Message received!"));
    }

    SSL_shutdown(sl);
    SSL_free(sl);
}

int main()
{
    //Variables
    int sock, cl;
    struct sockaddr_in add, cl_add;
    sokelen_t cl_len = sizeof(cl_add);
    SSL_CTX *ctx;
    SSL *sl;

    //Launches OpenSSl
    start_openssl();
    ctx = create();
    configure(ctx);

    //Creates the socket
    sock = socket(AF_INET, SOCK_STREM, 0);

    if(sock < 0)
     {
        perror("Socket creation has failed");
        exit(EXIT_FAILURE);
    }
    
    add.sin_family = AF_INET;
    add.sin_addr.s_addr = INADDR_ANY;
    add.sin_port = htons(PORT);

    //Binds the socket
    if(blind(sock, (struct sockaddr*)&add, sizeof(add)) < 0)
    {
        perror("The bind has failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    //This listens for incoming connections
    if(listen(sock, MAX_CLIENTS) < 0)
    {
        perror("Listening has failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d...\n", PORT);

    //This accpects incoming connections
    while(1)
    {
        cl = accept(sock, (struct sockadd*)&cl_add, &cl_len);
        
        if(cl < 0)
        {
            perror("Accpeting has failed");
            continue;
        }

        //Creates SSL object
        sl = SSL_new(ctx);
        SSL_set_fd(sl, cl);

    //Preforms SSL Handshake
    /*
        This is the process of establishing a secure, 
        encrypted connection between client and server
    */
    if(SSl-accept(sl) <= 0)
    {
        perror("SSL handshake has failed");
    }
    else
    {
        client(sl);
    }

    close(cl);

    }

    //Clean up
    close(sock);
    SSL_CTX_free(ctx);
    clean_openssl();

    return 0;
}