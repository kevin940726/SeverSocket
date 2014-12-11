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

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

#define BLEN 1200

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
    
    if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        errexit("Bind error.");
    
    if (listen(s, SOMAXCONN) < 0)
        errexit("Listen error.");
    
    return s;
}

struct passData{
    std::string ip;
    int portno;
    int sdc;
};

void *clientThread(void *clientData){
    std::string name, ip;
    int portno, sdc;
    passData newClient = *(passData*) clientData;
    ip = newClient.ip ;
    portno =  newClient.portno;
    sdc = newClient.sdc;
    std::cout << "Connected from " << ip << ":" << portno << std::endl;
    
    char buf[BLEN];
    char *bptr = buf;
    ssize_t buflen = sizeof(buf);
    memset(buf, 0, BLEN);
    
    regex_t reg_regex;
    std::string reg = "(.*)#(.*)";
    regcomp(&reg_regex, reg.c_str(), REG_EXTENDED);
    regmatch_t matches[3];
    
    while (true){
        if (recv(sdc, bptr, buflen, 0) > 0){
            buf[strlen(buf) - 2] = '\0';
            
            if (regexec(&reg_regex, buf, 3, matches, 0) == 0){
                buf[matches[1].rm_eo] = 0;
                if (!strcmp(buf + matches[1].rm_so, "REGISTER")){
                    buf[matches[2].rm_eo] = 0;
                    name = std::string(buf + matches[2].rm_so);
                    if (!search(lists, name)) lists.push_back(*new user(name, ip, portno));
                    send(sdc, "100 OK\n", 8, 0);
                    std::cout << printList(lists);
                }
                else if (search(lists, buf + matches[1].rm_so)){
                    buf[matches[2].rm_eo] = 0;
                    if (portno == strtoul(buf+ matches[2].rm_so, NULL, 0)){
                        send(sdc, printList(lists).c_str(), strlen(printList(lists).c_str()), 0);
                    }
                    else{
                        send(sdc, "220 AUTH_FAIL\n", 15, 0);
                    }
                }
            }
            else if (!strcmp(buf, "List")){
                send(sdc, printList(lists).c_str(), strlen(printList(lists).c_str()), 0);
            }
            else if (!strcmp(buf, "Exit")){
                send(sdc, "Bye\n", 3, 0);
                remove(&lists, name);
                break;
            }
            else{
                send(sdc, "Unknown syntax error.\n", 23, 0);
            }
            
            memset(buf, 0, BLEN);
        }
    }
    
    shutdown(sdc, SHUT_RDWR);
    return 0;
}

int main(int argc, const char * argv[]) {
    int sd = passivesock(5900);
    int sdc;
    
    struct sockaddr_in clientAddr;
    socklen_t addrlen = sizeof(clientAddr);
    
    int threadCount = 0;
    pthread_t *thread;
    thread = new pthread_t[threadCount];
    
    passData newClient;
    
    while (true){
        if ((sdc = accept(sd, (struct sockaddr *)&clientAddr, &addrlen)) > 0){
            newClient.ip = inet_ntoa(clientAddr.sin_addr);
            newClient.portno = (int) ntohs(clientAddr.sin_port);
            newClient.sdc = sdc;
            pthread_create(&thread[threadCount], NULL, clientThread, &newClient);
            threadCount++;
        }
    }
    
    return 0;
}
