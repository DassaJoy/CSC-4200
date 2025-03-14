//All Libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h> // converts IP addresses between text and binary format; converts values between host and network byte order
#include <openssl/ssl.h> // provides cryptographic functions and Secure Sockets Layer / Transport Layer Security
#include <openssl/err.h> // provides functions for handling and repoting OpenSSl errors
#include <pthread.h>

#define PORT 8080
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024
#define LOG_FILE "server.log"

FILE *log_file;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

//Function to log messages to a file
void log_message(const char *mess)
{
    pthread_mutex_lock(&log_mutex);
    log_file = fopen(LOG_FILE, "a");

    if (log_file)
    {
        fprintf(log_file, "%s\n", mess);
        fclose(log_file);
    }

    pthread_mutex_unlock(&log_mutex);
}

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

    m = TLS_server_method();
    ctx = SSL_CTX_new(m);

    if(!ctx)
    {
        log_message("Failed to create the SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

//Function that configures SSL
void configure(SSL_CTX *ctx)
{
    if(SSL_CTX_use_certificate_file(ctx, "ssl_certs/server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        log_message("Unable to load the certificate file");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if(SSL_CTX_use_PrivateKey_file(ctx, "ssl_certs/server.key", SSL_FILETYPE_PEM) <= 0)
    {
        log_message("Unable to load the private key file");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if(!SSL_CTX_check_private_key(ctx))
    {
        log_message("Private key does not match the public certificate");
        exit(EXIT_FAILURE);
    }
}

//Function that handles the client communication
void *client(void *sl)
{
    //Varibles
    SSL *new_sl = (SSL *)sl;
    char size[BUFFER_SIZE];
    int byte;

    //Receives message from client
    byte = SSL_read(new_sl, size, sizeof(size));

    if(byte <= 0)
    {
        log_message("SSL read has failed");
        ERR_print_errors_fp(stderr);
    }
    else
    {
        size[byte] = "\0";
        log_message(size);
        printf("Received: %s\n", size);

        //Sends confirmation 
        SSL_write(new_sl, "Message received!", strlen("Message received!"));
    }

    SSL_shutdown(new_sl);
    SSL_free(new_sl);
    pthread_exit(NULL);
}

int main()
{
    //Variables
    int sock, cl_sock;
    struct sockaddr_in add, cl_add;
    socklen_t cl_len = sizeof(cl_add);
    SSL_CTX *ctx;
    SSL *sl;
    pthread_t thread_id;

    //Launches OpenSSl
    start_openssl();
    ctx = create();
    configure(ctx);

    //Creates the socket
    sock = socket(AF_INET, SOCK_STREAM, 0);

    if(sock < 0)
     {
        perror("Socket creation has failed");
        exit(EXIT_FAILURE);
    }
    
    add.sin_family = AF_INET;
    add.sin_addr.s_addr = INADDR_ANY;
    add.sin_port = htons(PORT);

    //Binds the socket
    if(bind(sock, (struct sockaddr*)&add, sizeof(add)) < 0)
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
    log_message("Server has started");

    //This accpects incoming connections
    while(1)
    {
        cl_sock = accept(sock, (struct sockaddr*)&cl_add, &cl_len);
        
        if(cl_sock < 0)
        {
            perror("Accpeting has failed");
            continue;
        }

        //Creates SSL object
        sl = SSL_new(ctx);
        SSL_set_fd(sl, cl_sock);

        //Preforms SSL Handshake
        /*
            This is the process of establishing a secure, 
            encrypted connection between client and server
        */
        if(SSL_accept(sl) <= 0)
        {
            log_message("SSL handshake has failed");
            ERR_print_errors_fp(stderr);
            SSL_free(sl);
            close(cl_sock);
            continue;
        }
        
        log_message("Client is connected");

        // Create a new thread for each client
        if(pthread_create(&thread_id, NULL, client, (void *)sl) != 0)
        {
            log_message("Failed to create thread");
        }

        pthread_detach(thread_id);

    }

    //Clean up
    close(sock);
    SSL_CTX_free(ctx);
    clean_openssl();
    pthread_mutex_destroy(&log_mutex);

    return 0;
}