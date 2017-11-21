# phttp

phttp is a tiny HTTP/1.1 embeddable C++11 server library that aims to be correct and robust, but very low on features. It is intended to be used to build small HTTP serving infrastructure, that is not open to the general outside world, but instead serves up an interface to a browser accessing it via http://localhost, or an internal network service.

phttp was originally built to act as a gateway into local OS resources which are not exposed through the regular browser Javascript API.

Although generally low on features, phttp does support WebSockets.

phttp only uses poll(), and it supports Linux and Windows (Vista+). phttp does not try particularly hard to be ultra efficient. For example, it uses std::string and other such things. However, it does avoid wasteful memory copies, so for the intended use case, performance should not be a problem.

A simple server:

```cpp
phttp::Initialize();
phttp::Server server;
auto handler = [](phttp::Response& w, phttp::Request& r) {
	w.Body = "Hello!";
};
server.ListenAndRun("127.0.0.1", 8080, handler);
```

The entire architecture is single threaded and synchronous, which allows it to be very simple.

When using WebSockets, you can send a websocket frame from another thread.

The demo application `demo.cpp` illustrates all of the intended usage scenarios.

## Installation
Just incorporate the source files into your project, however you see fit.

On Windows, before running a server, you must call `phttp::Initialize()`. This is just a
wrapper around `WSAStartup()`.

## Attribution

This project uses:
* http11 parser by Zed A. Shaw and Mongrel2 Project Contributors
* SHA1 by Dr Brian Gladman, Worcester, UK

License: MIT
Author: Ben Harper (github.com/bmharper/phttp)
