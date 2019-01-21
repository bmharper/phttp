# phttp

phttp is a small HTTP/1.1 embeddable C++11 server library that aims to be correct and robust, but very low on features. phttp listens for network traffic from a single thread, but multiple threads can write responses (whether they are HTTP or WebSocket frames).

phttp only uses `poll()`, and it supports Linux and Windows (Vista+). phttp does not try to be ultra efficient. For example, it uses std::string and other such things.

A simple server:

```cpp
phttp::Initialize();
phttp::Server server;
auto handler = [](phttp::Response& w, phttp::Request& r) {
	w.Body = "Hello!";
};
server.ListenAndRun("127.0.0.1", 8080, handler);
```

The demo application `demo.cpp` illustrates some of the intended usage scenarios.

## Installation
Just incorporate the source files into your project, however you see fit.

On Windows, before running a server, you must call `phttp::Initialize()`. This is just a
wrapper around `WSAStartup()`.

## Threading Model
All socket _input_ is performed from a single thread, via the `Recv()` function. This function performs blocking IO,
using `poll`.
Socket output can be performed from any thread.

## Testing

	cd tests
	make server
	go run test.go

## Attribution

This project uses:
* http11 parser by Zed A. Shaw and Mongrel2 Project Contributors
* SHA1 by Dr Brian Gladman, Worcester, UK
* Semaphore by Jeff Preshing

License: MIT
Author: Ben Harper (github.com/bmharper/phttp)
