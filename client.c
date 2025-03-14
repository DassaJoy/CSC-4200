// All Libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> // converts IP addresses between text and binary format; converts values between host and network byte order
#include <openssl/ssl.h> // provides cryptographic functions and Secure Sockets Layer / Transport Layer Security
#include <openssl.err.h> // provides functions for handling and repoting OpenSSl errors

#define SERVER_IP "127.0.01"
#define PORT 8080
#define BUFFER_SIZE 1024

//Function to start openssl
/*
    OpenSSL proceds crytopgraphic funtionality 
    and secure sockets layer protocols
*/
void start_openssl()
{
    SSL_load_error_strings();
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

    m = TLS_client_method();
    ctx = SSL_CTX_new(m);

    if(!ctx)
    {
        perror("Not able to create SSL");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

//Function that communicates with the server
void communicate_server(SSL *sl)
{
    char size[BUFFER_SIZE];

    //This gets user's input
    printf("Enter message: ");
    fgets(size, sizeof(size), stdin);

    //This sends the message to server
    SSL_write(sl, size, strlen(buffer));

    //Reads the server's response
    int byte = SSL_read(sl, size, sizeof(size));

    if(byte <= 0)
    {
        perror("SSL read has failed");
    }
    else
    {
        size[byte] = '\0';
        printf("Server response: %s\n", size);
    }
}

int main()
{
    //Varibales
    int sock;
    struct sockaddr_in add;
    SSL_CTX *ctx;
    SSL *sl;

    //Launches OpenSSl
    start_openssl();
    ctx = create();

    //Creates the socket
    sock = socket(AF_INET, SOCK_STREM, 0);

    if(sock < 0)
    {
        perror("Socket creation has failed");
        exit(EXIT_FAILURE);
    }

    //sockaddr_in fields
    add.sin_famaily = AF_INET;
    add.sin_port = htons(PORT);
    add.sin_addr.s_addr = inet_addr(SERVER_IP);

    //Connection to the server
    if(connect(sock, (struct sockadd*)&add, sizeof(add)) < 0)
    {
        perror("Connection has failed");
        exit(EXIT_FAILURE);
    }

    //Creates SSL object
    sl = SSL_new(ctx);
    SSL_set_fd(sl, sock);

    //Preforms SSL Handshake
    /*
        This is the process of establishing a secure, 
        encrypted connection between client and server
    */
    if(SSL_connect(sl) < 0)
    {
        perror("SSL handshake has failed");
    }
    else
    {
        communication_server(sl);
    }

    close(sock);
    SSL_free(sl);
    clean_openssl();

    return 0;
}