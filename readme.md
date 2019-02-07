# phttp

phttp is a small HTTP/1.1 embeddable C++11 server library that aims to be correct and robust, but very low on features. phttp listens for network traffic from a single thread, but multiple threads can write responses.

* Runs on Linux (Clang/GCC)
* Runs on Windows (MSVC)
* Supports WebSockets
* Does not spawn any threads itself, but you are free to use as many threads as you need to serve your responses
* Uses non-blocking IO, which allows you to detect and throttle back the transmission of large responses
* Exposes an interface to provide transparent gzip/deflate compression to outgoing responses
* Logs can be written to your own logging interface
* Uses the machine-generated HTTP header parser by Zed Shaw, which has never had a security vulnerability
* Uses `poll`, so it doesn't scale beyond a thousand or so connections
* No support for TSL/SSL

A simple server:

```cpp
phttp::Initialize();
phttp::Server server;
auto handler = [](phttp::Response& w, phttp::RequestPtr r) {
	w.Body = "Hello! " + r->Path;
};
server.ListenAndRun("127.0.0.1", 8080, handler);
```

The demo application `demo.cpp` illustrates some of the intended usage scenarios.

## Installation
Just incorporate the source files into your project, however you see fit.
The three files that you need to compile and link to are `phttp.cpp`, `sha1.c`, `http11/http11_parser.c`
All C functions are prefixed with `phttp_`, to avoid name conflicts if you import a `SHA1` library from
elsewhere.

On Windows, before running a server, you must call `phttp::Initialize()`. This is just a
wrapper around `WSAStartup()`.

## Threading Model
All socket _input_ is performed from a single thread, via the `Recv()` function. This function uses `poll` to
determine which sockets are ready to be read/written.
Socket output can be performed from any thread.

## Testing

On Windows, open a `Visual Studio Command Prompt`. You must have WSL and Go installed.

	wsl WINDOWS=1 make -s -j build/server.exe && go run tests/test.go

On Linux

	make -s -j build/server && go run tests/test.go

## Scalability
The use of `poll` introduces a hard O(N) factor every time we ask the OS for more data, where N is the number
of TCP sockets that we have open. On Linux, one could change this code to use `epoll` pretty easily.

Windows does not support anything like `epoll`, so one would need to switch to IOCP. This would require
a non-trivial amount of code, but it might be possible to do it without introducing too much platform-specific switches etc.
However, not a lot of people are writing server-side C++ code on Windows these days, so there's probably not much call for this.

## Attribution

This project uses:
* http11 parser by Zed A. Shaw and Mongrel2 Project Contributors
* SHA1 by Dr Brian Gladman, Worcester, UK
* Semaphore by Jeff Preshing

License: MIT
Author: Ben Harper (github.com/bmharper/phttp)
