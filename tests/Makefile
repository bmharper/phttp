ifdef shell
	CXX=clang++ -std=c++11 -ggdb -lpthread
	CXX_SERVER=-o server
	CXX_UNIT=-o unit
	SERVER=server
	UNIT=unit
else
	CXX=cl.exe /Zi /EHsc /O2
	CXX_SERVER=/Feserver.exe
	CXX_UNIT=/Feserver.exe
	SERVER=server.exe
	UNIT=unit.exe
endif

$(SERVER): server.cpp ../phttp.cpp ../sha1.c ../http11/http11_parser.c
	$(CXX) $(CXX_SERVER) server.cpp ../phttp.cpp ../sha1.c ../http11/http11_parser.c

$(UNIT): unit.cpp ../phttp.cpp ../sha1.c ../http11/http11_parser.c
	$(CXX) $(CXX_UNIT) unit.cpp ../phttp.cpp ../sha1.c ../http11/http11_parser.c