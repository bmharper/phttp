CXX=clang++ -std=c++11 -ggdb -lpthread -o server
SERVER=server
# Uncoment to test MSVC compiler
CXX=cl.exe /Zi /EHsc /Feserver.exe
SERVER=server.exe

$(SERVER): server.cpp ../phttp.cpp ../sha1.c ../http11/http11_parser.c
	$(CXX) server.cpp ../phttp.cpp ../sha1.c ../http11/http11_parser.c