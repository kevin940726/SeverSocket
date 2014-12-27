# MakeFile
all:main.cpp
	g++ -I/usr/local/ssl/include main.cpp -o main /usr/local/ssl/lib/libssl.a /usr/local/ssl/lib/libcrypto.a -lssl -lcrypto -lcurl -lpthread
clean:
	rm -f main