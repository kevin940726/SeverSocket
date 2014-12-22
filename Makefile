# MakeFile
all:main.cpp
	g++ -o main main.cpp -lpthread
clean:
	rm -f main