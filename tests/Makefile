CXX=clang++ -std=c++11 -ggdb -lpthread -o server
SERVER=server

# Uncoment to test MSVC compiler
CXX=cl.exe /Zi /EHsc /Feserver.exe
SERVER=server.exe
UNIT=unit.exe

$(SERVER): server.cpp ../phttp.cpp ../sha1.c ../http11/http11_parser.c
	$(CXX) server.cpp ../phttp.cpp ../sha1.c ../http11/http11_parser.c

$(UNIT): unit.cpp ../phttp.cpp ../sha1.c ../http11/http11_parser.c
	$(CXX) unit.cpp ../phttp.cpp ../sha1.c ../http11/http11_parser.c Ws2_32.lib /Feunit.exe