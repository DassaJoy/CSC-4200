// All Libraries
#include <stdio.h> // allows the program to use functions from the Standard Input Output (stdio) Library
#include <unistd.h> // essentail in Unix/Linux-based systems and provides access to the Portable Operating Sysstem Interface API (commonly used for system calls related to process control, file operations, and system interaction)
#include <stdlib.h> // provides functions for memory management, process control, conversions, and other general-purpose utilites (part of the Standard Library)
#include <string.h> // provides functions for manipulating and handling C-style strings (essential when working with text-based in C)
#include <arpa/inet.h> // converts IP addresses between text and binary format; converts values between host and network byte order
#include <openssl/ssl.h> // provides cryptographic functions and Secure Sockets Layer / Transport Layer Security
#include <openssl/err.h> // provides functions for handling and repoting OpenSSl errors

// Symbolic Constants
#define SERVER_IP "127.0.0.1"
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

// Function that communicates with the server
/*
    Handles user input, sends it to the server via SSL
    and waits for and prints the server's response
*/
void communicate_server(SSL *sl)
{
    char size[BUFFER_SIZE];

    // This gets user's input
    printf("Enter message: ");
    fgets(size, sizeof(size), stdin);

    // This sends the message to server
    SSL_write(sl, size, strlen(size));

    // Reads the server's response
    int byte = SSL_read(sl, size, sizeof(size));

    // Checks if SSL_read failed
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
    // Varibales
    int sock;
    struct sockaddr_in add;
    SSL_CTX *ctx;
    SSL *sl;

    // Launches OpenSSl
    start_openssl();
    ctx = create();

    // Creates the socket
    sock = socket(AF_INET, SOCK_STREAM, 0);

    // Checks to see if the creation of socket worked
    if(sock < 0)
    {
        perror("Socket creation has failed");
        exit(EXIT_FAILURE);
    }

    // sockaddr_in fields
    add.sin_family = AF_INET; // specifies the address family 
    add.sin_port = htons(PORT); // stores the port number, must be in network byte order
    add.sin_addr.s_addr = inet_addr(SERVER_IP); //stores the IPv4 address, in network byte order

    // Checks connection to the server
    if(connect(sock, (struct sockaddr*)&add, sizeof(add)) < 0)
    {
        perror("Connection has failed");
        exit(EXIT_FAILURE);
    }

    // Creates SSL object
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
        communicate_server(sl);
    }

    // Clean up
    close(sock);
    SSL_free(sl);
    clean_openssl();

    return 0;
}