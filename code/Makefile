all:
	g++ -std=c++17 -pthread server.cpp func.cpp -o server -lssl -lcrypto
	g++ -std=c++17 -pthread client.cpp func.cpp -o client -lssl -lcrypto