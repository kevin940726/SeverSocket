#include <iostream>
#include <string>
#include <sstream>
#include <list>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef server_class_h
#define server_class_h

class user{
private:
    std::string name;
    std::string ip;
    int portno;
public:
    user() {this->name = ""; this->ip = ""; this->portno = 0;}
    user(std::string name, std::string ip, int portno)
        {this->name = name; this->ip = ip; this->portno = portno;}
    std::string getName() {return this->name;}
    std::string getIp() {return this->ip;}
    int getPort() {return this->portno;}
};

std::string printList(std::list<user> lists){
    if (lists.empty()) return "No target in list.\n";
    std::stringstream ss;
    ss << lists.size() << "\n";
    for (std::list<user>::iterator it = lists.begin(); it != lists.end(); it++){
        ss << it->getName() << "#" << it->getIp() << "#" << it->getPort() << "\n";
    }
    return ss.str();
}

void remove(std::list<user> *lists, std::string name){
    for (std::list<user>::iterator it = lists->begin(); it != lists->end(); it++){
        if (it->getName() == name){
            lists->erase(it);
            return;
        }
    }
}

bool search(std::list<user> lists, std::string name){
    for (std::list<user>::iterator it = lists.begin(); it != lists.end(); it++){
        if (it->getName() == name){
            return true;
        }
    }
    return false;
}

SSL_CTX* InitServerCTX(void)
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
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


#endif
