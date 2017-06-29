CXX=clang++ -std=c++11 -lpthread
demo: demo.cpp phttp.cpp sha1.c http11/http11_parser.c
	$(CXX) -o demo demo.cpp phttp.cpp sha1.c http11/http11_parser.c

