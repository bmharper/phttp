CXX=clang++ -std=c++11 -ggdb -lpthread
server: server.cpp ../phttp.cpp ../sha1.c ../http11/http11_parser.c
	$(CXX) -o server server.cpp ../phttp.cpp ../sha1.c ../http11/http11_parser.c