#include <iostream>
#include <string>
#include <sstream>
#include <list>

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

#endif
