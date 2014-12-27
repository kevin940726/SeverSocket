#include "class.h"

#include <iostream>
#include <string>
#include <cstdlib>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <regex.h>
#include <pthread.h>
#include <list>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BLEN 1024

std::list<user> lists;

void errexit(std::string message){
    std::cout << message << std::endl;
    exit(1);
}

int passivesock(u_short service){
    struct sockaddr_in sin;
    int s;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(service);
    
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        errexit("Failed to create socket.");
    
    bool sock_opt = true;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&sock_opt, sizeof(bool));
    
    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        errexit("Bind error.");
    
    if (listen(s, SOMAXCONN) < 0)
        errexit("Listen error.");
    
    return s;
}

SSL_CTX* InitServerCTX(void)
{
    //SSL_METHOD *method;
    SSL_CTX *ctx;
    
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    //method = SSLv3_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(SSLv3_server_method());   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
    
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        std::cout << "Server certificates:" << std::endl;
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        std::cout << "Subject: " << line << std::endl;
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        std::cout << "Issuer: " << line << std::endl;
        free(line);
        X509_free(cert);
    }
    else
        std::cout << "No certificates" << std::endl;
}

struct passData{
    std::string ip;
    int portno;
    int sdc;
    SSL* ssl;
};

void *clientThread(void *clientData){
    std::string name, ip;
    int portno, sdc;
    ssize_t rec;
    passData newClient = *(passData*) clientData;
    ip = newClient.ip ;
    portno =  newClient.portno;
    sdc = newClient.sdc;
    SSL* ssl = newClient.ssl;
    std::cout << "Connected from " << ip << ":" << portno << std::endl;
    ShowCerts(ssl);
    
    if ( SSL_accept(ssl) == -1 ) errexit("ssl");
    
    char buf[BLEN];
    char *bptr = buf;
    ssize_t buflen = sizeof(buf);
    memset(buf, 0, BLEN);
    
    regex_t reg_regex;
    std::string reg = "(.*)#(.*)";
    regcomp(&reg_regex, reg.c_str(), REG_EXTENDED);
    regmatch_t matches[3];
    
    while (true){
        if ((rec = SSL_read(ssl, bptr, buflen)) > 0){
            if (regexec(&reg_regex, buf, 3, matches, 0) == 0){
                buf[matches[1].rm_eo] = 0;
                if (!strcmp(buf + matches[1].rm_so, "REGISTER")){
                    buf[matches[2].rm_eo] = 0;
                    name = std::string(buf + matches[2].rm_so);
                    if (!search(lists, name)) lists.push_back(*new user(name, ip, portno));
                    SSL_write(ssl, "100 OK\n", 8);
                    std::cout << printList(lists);
                }
                else if (search(lists, buf + matches[1].rm_so)){
                    buf[matches[2].rm_eo] = 0;
                    if (portno == strtoul(buf+ matches[2].rm_so, NULL, 0)){
                        SSL_write(ssl, printList(lists).c_str(), strlen(printList(lists).c_str()));
                    }
                    else{
                        SSL_write(ssl, "220 AUTH_FAIL\n", 15);
                    }
                }
                else{
                    SSL_write(ssl, "220 AUTH_FAIL\n", 15);
                }
            }
            else if (!strcmp(buf, "List")){
                SSL_write(ssl, printList(lists).c_str(), strlen(printList(lists).c_str()));
            }
            else if (!strcmp(buf, "Exit")){
                SSL_write(ssl, "Bye\n", 3);
                break;
            }
            else{
                SSL_write(ssl, "Unknown syntax error.\n", 23);
            }
            
            memset(buf, 0, BLEN);
        }
        else if (rec == 0) break;
    }
    
    remove(&lists, name);
    std::cout << "Disconnected from " << ip << ":" << portno << std::endl;
    sdc = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);
    shutdown(sdc, SHUT_RDWR);
    return 0;
}

int main(int argc, const char * argv[]) {
    u_short portno = 6900;
    if (argc == 2) portno = strtol(argv[1], NULL, 10);
    int sd = passivesock(portno);
    int sdc;
    
    SSL_CTX *ctx;
    SSL_library_init();
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mykey.pem");
    
    struct sockaddr_in clientAddr;
    socklen_t addrlen = sizeof(clientAddr);
    
    int threadCount = 0;
    pthread_t *thread;
    thread = new pthread_t[threadCount+1];
    
    passData newClient;
    
    std::cout << "Waiting..." << std::endl;
    while (true){
        if ((sdc = accept(sd, (struct sockaddr *)&clientAddr, &addrlen)) > 0){
            SSL *ssl;
            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, sdc);
            
            newClient.ip = inet_ntoa(clientAddr.sin_addr);
            newClient.portno = (int) ntohs(clientAddr.sin_port);
            newClient.sdc = sdc;
            newClient.ssl = ssl;
            
            pthread_create(&thread[threadCount], NULL, clientThread, &newClient);
            threadCount++;
        }
        else if (sdc == 0) break;
    }
    shutdown(sd, SHUT_RDWR);
    SSL_CTX_free(ctx);
    
    return 0;
}
