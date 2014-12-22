SeverSocket
===========

How to compile:
    cd to the directory, type "make" to generate the binary file to execute. Or type "g++ -o main main.cpp lpthread" to do the same thing.

How to run the program:
    Type "./main" to run the program to open the port number "6900".
    Type "./main PORTNO" to run the program with any port number you like that > 1024.
    
About the program:
    The first running would print "Waiting..." that indicates the program doesn't fail.
    Any client connect to the server will print "Connect from IP:PORT".
    Any client close the connection by either type in "Exit" or close the client program will print "Disconnect from IP:PORT".
    Any client that succeed to register will print the current list of clients.

Recommanded enviroment:
    Any Linux-like OS, that support c++ with pthread.