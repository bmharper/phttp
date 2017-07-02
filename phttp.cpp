#include <stdint.h>
#include <stdio.h>
#include <algorithm>
#include <assert.h>
#include <time.h>
#include <string.h>
#include "phttp.h"
#include "http11/http11_parser.h"
#include "sha1.h"

#ifdef _WIN32
#include <io.h>
#else
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable : 4996) // sprintf
#endif

typedef unsigned char byte;

namespace phttp {

#ifdef _WIN32
static const uint32_t Infinite        = INFINITE;
static const int      ErrSOCKET_ERROR = SOCKET_ERROR;
#else
static const uint32_t Infinite        = 0xFFFFFFFF;
static const int      ErrSOCKET_ERROR = -1;
inline int            closesocket(int fd) { return close(fd); }
#endif

#ifdef max
#undef max
#endif

#ifdef min
#undef min
#endif

static const char* StatusMsg(int code) {
	switch (code) {
	case Status100_Continue: return "Continue";
	case Status101_Switching_Protocols: return "Switching Protocols";
	case Status102_Processing: return "Processing";
	case Status200_OK: return "OK";
	case Status201_Created: return "Created";
	case Status202_Accepted: return "Accepted";
	case Status203_Non_Authoritative_Information: return "Non Authoritative Information";
	case Status204_No_Content: return "No Content";
	case Status205_Reset_Content: return "Reset Content";
	case Status206_Partial_Content: return "Partial Content";
	case Status207_Multi_Status: return "Multi Status";
	case Status208_Already_Reported: return "Already Reported";
	case Status226_IM_Used: return "IM Used";
	case Status300_Multiple_Choices: return "Multiple Choices";
	case Status301_Moved_Permanently: return "Moved Permanently";
	case Status302_Found: return "Found";
	case Status303_See_Other: return "See Other";
	case Status304_Not_Modified: return "Not Modified";
	case Status305_Use_Proxy: return "Use Proxy";
	case Status307_Temporary_Redirect: return "Temporary Redirect";
	case Status308_Permanent_Redirect: return "Permanent Redirect";
	case Status400_Bad_Request: return "Bad Request";
	case Status401_Unauthorized: return "Unauthorized";
	case Status402_Payment_Required: return "Payment Required";
	case Status403_Forbidden: return "Forbidden";
	case Status404_Not_Found: return "Not Found";
	case Status405_Method_Not_Allowed: return "Method Not Allowed";
	case Status406_Not_Acceptable: return "Not Acceptable";
	case Status407_Proxy_Authentication_Required: return "Proxy Authentication Required";
	case Status408_Request_Timeout: return "Request Timeout";
	case Status409_Conflict: return "Conflict";
	case Status410_Gone: return "Gone";
	case Status411_Length_Required: return "Length Required";
	case Status412_Precondition_Failed: return "Precondition Failed";
	case Status413_Payload_Too_Large: return "Payload Too Large";
	case Status414_URI_Too_Long: return "URI Too Long";
	case Status415_Unsupported_Media_Type: return "Unsupported Media Type";
	case Status416_Range_Not_Satisfiable: return "Range Not Satisfiable";
	case Status417_Expectation_Failed: return "Expectation Failed";
	case Status421_Misdirected_Request: return "Misdirected Request";
	case Status422_Unprocessable_Entity: return "Unprocessable Entity";
	case Status423_Locked: return "Locked";
	case Status424_Failed_Dependency: return "Failed Dependency";
	case Status425_Unassigned: return "Unassigned";
	case Status426_Upgrade_Required: return "Upgrade Required";
	case Status427_Unassigned: return "Unassigned";
	case Status428_Precondition_Required: return "Precondition Required";
	case Status429_Too_Many_Requests: return "Too Many Requests";
	case Status430_Unassigned: return "Unassigned";
	case Status431_Request_Header_Fields_Too_Large: return "Request Header Fields Too Large";
	case Status500_Internal_Server_Error: return "Internal Server Error";
	case Status501_Not_Implemented: return "Not Implemented";
	case Status502_Bad_Gateway: return "Bad Gateway";
	case Status503_Service_Unavailable: return "Service Unavailable";
	case Status504_Gateway_Timeout: return "Gateway Timeout";
	case Status505_HTTP_Version_Not_Supported: return "HTTP Version Not Supported";
	case Status506_Variant_Also_Negotiates: return "Variant Also Negotiates";
	case Status507_Insufficient_Storage: return "Insufficient Storage";
	case Status508_Loop_Detected: return "Loop Detected";
	case Status509_Unassigned: return "Unassigned";
	case Status510_Not_Extended: return "Not Extended";
	case Status511_Network_Authentication_Required: return "Network Authentication Required";
	default: return "Unknown Code";
	}
}

const char* WeekDay[7] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};

const char* Months[12] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

static void MakeDate(char* buf) {
	tm m;
#ifdef _WIN32
	__int64 t;
	_time64(&t);
	_gmtime64_s(&m, &t);
#else
    time_t t = time(nullptr);
    gmtime_r(&t, &m);
#endif
	sprintf(buf, "%s, %02d %s %04d %02d:%02d:%02d GMT", WeekDay[m.tm_wday], m.tm_mday, Months[m.tm_mon], m.tm_year + 1900, m.tm_hour, m.tm_min, m.tm_sec);
}

static uint64_t uatoi64(const char* s, size_t len) {
	uint64_t v = 0;
	for (size_t i = 0; i < len; i++)
		v = v * 10 + (s[i] - '0');
	return v;
}

static bool EqualsNoCase(const char* a, const char* b, size_t len) {
	for (size_t i = 0; i != len; i++) {
		int _a = a[i];
		int _b = b[i];
		_a     = (_a >= 'A' && _a <= 'Z') ? _a + 'a' - 'A' : _a;
		_b     = (_b >= 'A' && _b <= 'Z') ? _b + 'a' - 'A' : _b;
		if (_a != _b)
			return false;
	}
	return true;
}

static bool EqualsNoCase(const char* a, const char* b) {
	size_t i = 0;
	for (; a[i] && b[i]; i++) {
		int _a = a[i];
		int _b = b[i];
		_a     = (_a >= 'A' && _a <= 'Z') ? _a + 'a' - 'A' : _a;
		_b     = (_b >= 'A' && _b <= 'Z') ? _b + 'a' - 'A' : _b;
		if (_a != _b)
			return false;
	}
	return a[i] == 0 && b[i] == 0;
}

static const char* Base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void Base64EncodeTriple(uint8_t raw[3], char* enc) {
	enc[0] = Base64Table[raw[0] >> 2];
	enc[1] = Base64Table[63 & ((raw[0] << 4) | (raw[1] >> 4))];
	enc[2] = Base64Table[63 & ((raw[1] << 2) | (raw[2] >> 6))];
	enc[3] = Base64Table[63 & raw[2]];
}

static void Base64Encode(const uint8_t* raw, size_t len, char* enc) {
	size_t roundedLen = 3 * ((len + 2) / 3);
	for (uint32_t i = 0; i != roundedLen; i += 3, enc += 4) {
		uint8_t t[3];
		t[0] = raw[i];
		t[1] = i + 1 < len ? raw[i + 1] : 0;
		t[2] = i + 2 < len ? raw[i + 2] : 0;
		Base64EncodeTriple(t, enc);
	}
	if (roundedLen - len == 1) {
		enc[-1] = '=';
	} else if (roundedLen - len == 2) {
		enc[-2] = '=';
		enc[-1] = '=';
	}
	enc[0] = 0;
}

std::string Request::Header(const char* h) const {
	for (const auto& p : Headers) {
		if (EqualsNoCase(p.first.c_str(), h))
			return p.second;
	}
	return "";
}

bool Request::IsWebSocketUpgrade() const {
	// Chrome  (59) sends Connection: Upgrade
	// Firefox (53) sends Connection: keep-alive, Upgrade
	return Header("Upgrade") == "websocket" &&
	       Header("Connection").find("Upgrade") != -1;
}

size_t Response::FindHeader(const std::string& header) const {
	for (size_t i = 0; i < Headers.size(); i++) {
		if (EqualsNoCase(Headers[i].first.c_str(), header.c_str()))
			return i;
	}
	return -1;
}

void Response::SetHeader(const std::string& header, const std::string& val) {
	size_t i = FindHeader(header);
	if (i != -1)
		Headers[i].second = val;
	else
		Headers.push_back({header, val});
}

PHTTP_API bool Initialize() {
#ifdef _WIN32
	WSADATA wsaData;
	int     wsa_startup = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (wsa_startup != 0) {
		printf("WSAStartup failed: %d\n", wsa_startup);
		return false;
	}
#endif
	return true;
}

PHTTP_API void Shutdown() {
#ifdef _WIN32
	WSACleanup();
#endif
}

Server::Server() {
	memset(ClosePipe, 0, sizeof(ClosePipe));
}

bool Server::ListenAndRun(const char* bindAddress, int port, std::function<void(Response& w, Request& r)> handler) {
	StopSignal = false;
	Handler    = handler;
	if (!Log)
		Log = stdout;

	ListenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ListenSock == InvalidSocket) {
		fprintf(Log, "socket() failed: %d\n", LastError());
		return false;
	}

#ifndef _WIN32
	// This avoids "socket already in use" errors when frequently restarting server
	int optval = 1;
	setsockopt(ListenSock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	if (pipe(ClosePipe) == -1) {
		fprintf(Log, "pipe() failed: %d\n", LastError());
		return false;
	}
#endif

	sockaddr_in service = {0};
	service.sin_family  = AF_INET;
	inet_pton(AF_INET, bindAddress, &service.sin_addr);
	service.sin_port = htons(port);

	int err = ::bind(ListenSock, (sockaddr*) &service, sizeof(service));
	if (err == ErrSOCKET_ERROR) {
		fprintf(Log, "bind() on %s:%d failed: %d\n", bindAddress, port, LastError());
		Cleanup();
		return false;
	}

	if (listen(ListenSock, SOMAXCONN) == ErrSOCKET_ERROR) {
		fprintf(Log, "listen() on %s:%d failed: %d\n", bindAddress, port, LastError());
		Cleanup();
		return false;
	}

	BufCap = 4096;
	Buf    = (uint8_t*) malloc(BufCap);
	if (!Buf)
		return false;
	BufStart = Buf;
	BufEnd   = Buf;

	fprintf(Log, "Listening on port %d. ListenSocket = %d\n", (int) port, (int) ListenSock);

	// Socket is ready to accept connections
	Run();
	Cleanup();

	return true;
}

void Server::Stop() {
	StopSignal = true;
	if (ListenSock != InvalidSocket) {
#ifdef _WIN32
		closesocket(ListenSock);
		ListenSock = InvalidSocket;
#else
        // Write a dummy byte into ClosePipe, to wake poll() up, so we can exit cleanly.
        // The linux docs say that it's illegal to close() a socket from another thread,
        // while you're busy waiting on it with a select() or poll(), so we use a pipe
        // here instead.
        write(ClosePipe[1], "x", 1);
#endif
	}
}

bool Server::SendWebSocket(int64_t websocketID, RequestType type, const void* buf, size_t len) {
	if (type != TypeWebSocketBinary && type != TypeWebSocketText) {
		assert(false);
		return false;
	}
	std::lock_guard<std::mutex> lock(BigLock);
	return SendWebSocketInternal(websocketID, type, buf, len);
}

void Server::Run() {
// select() on linux can only monitor FDs that are below FD_SETSIZE, which is 1024 in glibc.
// Because of this, we must use poll() on linux.
#ifdef _WIN32
	while (!StopSignal) {
		BigLock.lock();
		fd_set   fds;
		socket_t maxSocket = ListenSock;
		FD_ZERO(&fds);
		FD_SET(ListenSock, &fds);
		for (auto r : Requests) {
			FD_SET(r->Sock, &fds);
			maxSocket = std::max(maxSocket, r->Sock);
		}
		BigLock.unlock();

		int n = select((int) (maxSocket + 1), &fds, nullptr, nullptr, nullptr);
		if (StopSignal)
			break;
		if (n <= 0)
			continue;

		BigLock.lock();
		if (FD_ISSET(ListenSock, &fds) && Requests.size() < MaxRequests)
			Accept();
		for (size_t i = 0; i < Requests.size(); i++) {
			BusyReq* r = Requests[i];
			if (FD_ISSET(r->Sock, &fds)) {
				if (!ReadFromRequest(r)) {
					CloseRequest(r);
					i--;
				}
			}
		}
		BigLock.unlock();
	}
#else // not _WIN32
    while (!StopSignal) {
        BigLock.lock();
        pollfd fds[MaxRequests + 2];
        int    nfds = 0;
        fds[nfds++] = {ListenSock, POLLIN, 0}; // code down below assumes ListenSock is fds[0]
        fds[nfds++] = {ClosePipe[0], POLLIN, 0};
        for (auto r : Requests) {
            fds[nfds++] = {r->Sock, POLLIN, 0};
        }

        BigLock.unlock();

        int n = poll(fds, nfds, -1);
        if (StopSignal)
            break;
        if (n <= 0)
            continue;

        BigLock.lock();
        if (!!(fds[0].revents & POLLIN) && Requests.size() < MaxRequests)
            Accept();
        for (size_t i = 0; i < Requests.size(); i++) {
            BusyReq* r = Requests[i];
            for (int j = 0; j < nfds; j++) {
                if (fds[j].fd == r->Sock) {
                    if (fds[j].revents) {
                        if (!ReadFromRequest(r)) {
                            CloseRequest(r);
                            i--;
                        }
                    }
                    break;
                }
            }
        }
        BigLock.unlock();
    }
#endif
}

void Server::Accept() {
	sockaddr_in addr;
	socklen_t   addr_len = sizeof(addr);
	socket_t    newSock  = accept(ListenSock, (sockaddr*) &addr, &addr_len);
	if (newSock == InvalidSocket) {
		fprintf(Log, "accept() failed: %d\n", LastError());
		return;
	}
	BusyReq* req      = new BusyReq();
	req->Sock         = newSock;
	req->ID           = NextReqID++;
	req->IsHeaderDone = false;
	req->Req          = new Request();
	auto parser       = new http_parser();
	http_parser_init(parser);
	parser->data           = req;
	parser->http_field     = cb_http_field;
	parser->request_method = cb_request_method;
	parser->request_uri    = cb_request_uri;
	parser->fragment       = cb_fragment;
	parser->request_path   = cb_request_path;
	parser->query_string   = cb_query_string;
	parser->http_version   = cb_http_version;
	parser->header_done    = cb_header_done;
	req->Parser            = parser;
	Requests.push_back(req);
	if (LogAllEvents)
		fprintf(Log, "[%5lld %5d] socked opened\n", (long long) req->ID, (int) req->Sock);
}

bool Server::ReadFromRequest(BusyReq* r) {
	int nread = recv(r->Sock, (char*) Buf, (int) BufCap, 0);
	if (nread < 0) {
		fprintf(Log, "[%5lld %5d] recv error %d %d. closing socket\n", (long long) r->ID, (int) r->Sock, nread, LastError());
		return false;
	} else if (nread == 0) {
		if (LogAllEvents)
			fprintf(Log, "[%5lld %5d] socket closed on recv\n", (long long) r->ID, (int) r->Sock);
		return false;
	}

	BufStart = Buf;
	BufEnd   = Buf + nread;

	bool ok;
	if (r->IsWebSocket)
		ok = ReadFromWebSocket(r);
	else
		ok = ReadFromHttpRequest(r);

	// Since every recv can be for a different request, we can't share the buffer between requests.
	BufStart = Buf;
	BufEnd   = Buf;

	return ok;
}

bool Server::ReadFromWebSocket(BusyReq* r) {
	// Loop over websocket data until we can't make any further progress.
	// If there is any data left in the buffer, then it means that
	// we have an incomplete header. The maximum size of a header is 14
	// bytes, so if we haven't made progress, and we have 14 bytes or
	// more inside our buffer, then we have a bug.
	byte* prevBufStart = BufStart - 1;
	while (BufStart != prevBufStart) {
		prevBufStart = BufStart;
		if (!ReadFromWebSocketLoop(r))
			return false;
	}
	// See comment above
	size_t len = BufLen();
	assert(len < 14);

	if (len != 0) {
		// The buffer in 'Buf' is shared by all connections, so we can't expect it to still be ours
		// when our next bytes come in on our TCP socket. So, if we were left with an incomplete header,
		// then we need to save those bytes for next time. This is a rare occurrence, so we don't mind
		// if it incurs some memmove penalties.
		memcpy(r->WebSockHeadBuf + r->WebSockHeadBufLen, BufStart, BufLen());
		r->WebSockHeadBufLen += BufLen();
	}

	return true;
}

bool Server::ReadFromWebSocketLoop(BusyReq* r) {
	if (!r->HaveWebSockHead) {
		if (!ReadWebSocketHead(r))
			return false;
	}
	if (!r->HaveWebSockHead)
		return true;

	ReadWebSocketBody(r);

	if (r->IsWebSockControlFrame()) {
		// lazy - just close TCP socket. Should send a return close frame, unless we initiated it.
		if (r->WebSockType == WebSocketFrameType::Close)
			return false;

		if (r->WebSockType == WebSocketFrameType::Ping) {
			if (!SendWebSocketPong(r))
				return false;
		}
	}

	if (r->WebSockPayloadRecv == r->WebSockPayloadLen) {
		// We could elect to dispatch continuation packets, but let's delay that until it's necessary. Could be an opt-in flag.
		if (r->IsWebSocketFin) {
			if (r->WebSockType == WebSocketFrameType::Binary || r->WebSockType == WebSocketFrameType::Text)
				DispatchWebSocketFrame(r);
			r->Req->Body.resize(0);
		}
		// Reset to receive another frame
		r->HaveWebSockHead    = false;
		r->IsWebSocketFin     = false;
		r->WebSockPayloadRecv = 0;
		r->WebSockPayloadLen  = 0;
		r->WebSockType        = WebSocketFrameType::Unknown;
		r->WebSockMaskPos     = 0;
		r->WebSockControlBody.resize(0);
		memset(r->WebSockMask, 0, 4);
	}
	return true;
}

bool Server::ReadWebSocketHead(BusyReq* r) {
	// This function might run more than once. It is extremely unlikely in practice, but it certainly
	// is possible. For example, if the client sends us one byte at a time, then this function will enter
	// multiple times, each time getting a little bit further, but giving up several times, before
	// declaring HaveWebSockHead = true.
	// We know that this function has insufficient data if BufStart does not move forward.

	// If our previous recv() left us with an incomplete header, then we need to add those bytes back in here.
	// To simplify this code, we always work off a static buffer of 14 bytes.
	// Not all 14 bytes are necessarily populated.

	byte   buf[14];
	size_t extraBytes = std::min(BufLen(), 14 - r->WebSockHeadBufLen);
	memcpy(buf, r->WebSockHeadBuf, r->WebSockHeadBufLen);
	memcpy(buf + r->WebSockHeadBufLen, BufStart, extraBytes);
	size_t bufLen = r->WebSockHeadBufLen + extraBytes;

	// Need 2nd byte for payload len. The shortest header is 2 bytes. The longest header is 14 bytes.
	if (bufLen < 2)
		return true;

	r->IsWebSocketFin = !!(buf[0] & 128);
	r->WebSockType    = (WebSocketFrameType)(buf[0] & 15);

	byte len1 = buf[1];
	if (!(len1 & 128)) {
		fprintf(Log, "[%5lld %5d] websocket client didn't mask request\n", (long long) r->ID, (int) r->Sock);
		return false;
	}
	r->WebSockPayloadLen = 0;
	len1 &= 127;
	size_t bytesOfLen = 0;
	if (len1 < 126) {
		// 7-bit length. 0..125
		r->WebSockPayloadLen = len1;
		bytesOfLen           = 1;
	} else if (len1 == 126 && bufLen >= 4) {
		// 16-bit length 126..65535
		r->WebSockPayloadLen = ((uint16_t) buf[2] << 8) | (uint16_t) buf[3];
		bytesOfLen           = 3;
	} else if (len1 == 127 && bufLen >= 10) {
		// 64-bit length 65536..LARGE
		r->WebSockPayloadLen = ((uint64_t) buf[2] << 56) |
		                       ((uint64_t) buf[3] << 48) |
		                       ((uint64_t) buf[4] << 40) |
		                       ((uint64_t) buf[5] << 32) |
		                       ((uint64_t) buf[6] << 24) |
		                       ((uint64_t) buf[7] << 16) |
		                       ((uint64_t) buf[8] << 8) |
		                       ((uint64_t) buf[9]);
		bytesOfLen = 9;
		assert(r->WebSockPayloadLen < 1000000);
	}

	if (bytesOfLen == 0)
		return true;

	// We have the payload length, now we need the mask

	size_t headerSize = 1 + bytesOfLen + 4;
	bool   haveMask   = bufLen >= headerSize;

	if (!haveMask)
		return true;

	memcpy(r->WebSockMask, buf + 1 + bytesOfLen, 4);
	r->HaveWebSockHead = true;
	BufStart += headerSize - r->WebSockHeadBufLen;
	r->WebSockHeadBufLen = 0;

	return true;
}

void Server::ReadWebSocketBody(BusyReq* r) {
	std::string& body = r->IsWebSockControlFrame() ? r->WebSockControlBody : r->Req->Body;

	size_t nread = std::min(BufLen(), r->WebSockPayloadLen - r->WebSockPayloadRecv);
	byte*  buf   = BufStart;
	char   mask[4];
	memcpy(mask, r->WebSockMask, 4);
	uint32_t mp = r->WebSockMaskPos;
	for (size_t i = 0; i < nread; i++, mp = (mp + 1) & 3)
		body += buf[i] ^ mask[mp];

	r->WebSockMaskPos = mp;
	r->WebSockPayloadRecv += nread;
	BufStart += nread;
}

bool Server::ReadFromHttpRequest(BusyReq* r) {
	auto parser = (http_parser*) r->Parser;
	if (!r->IsHeaderDone) {
		r->HttpHeadBuf.append((const char*) BufStart, BufLen());
		size_t oldPos = parser->nread;
		http_parser_execute(parser, r->HttpHeadBuf.c_str(), r->HttpHeadBuf.size(), parser->nread);
		BufStart += parser->nread - oldPos;
		if (!!http_parser_has_error(parser)) {
			fprintf(Log, "[%5lld %5d] http parser error\n", (long long) r->ID, (int) r->Sock);
			r->HttpHeadBuf.resize(0);
			return false;
		} else if (r->IsHeaderDone) {
			r->HttpHeadBuf.resize(0);
		}
	}

	// We don't need to worry about only copying a limited amount of bytes here, or checking
	// whether the incoming bytes are for the next HTTP request, because we are HTTP 1.1,
	// so we're half duplex. All bytes that are coming in are for this one request.
	// The server will wait for a response before sending another request.
	// WebSockets are full duplex, which is why their implementation is more complex.

	// It is normal for IsHeaderDone to be true now, even through it was false in the above block
	if (r->IsHeaderDone && BufLen() != 0)
		r->Req->Body.append((const char*) BufStart, BufLen());

	bool ok = true;
	if (r->IsHeaderDone && r->Req->Body.size() == r->Req->ContentLength) {
		ok = DispatchToHandler(r);
		delete r->Req;
		r->Req = new Request();
		if (r->IsWebSocket) {
			if (LogAllEvents)
				fprintf(Log, "[%5lld %5d] upgraded to websocket\n", (long long) r->ID, (int) r->Sock);
		} else {
			// Reset the parser for another request
			auto oldID      = r->ID;
			r->IsHeaderDone = false;
			auto parser     = (http_parser*) r->Parser;
			http_parser_init(parser);
			r->ID = NextReqID++;
			if (LogAllEvents)
				fprintf(Log, "[%5lld %5d] recycling socket (ID %lld) for another request\n", (long long) r->ID, (int) r->Sock, (long long) oldID);
		}
	}

	return ok;
}

bool Server::DispatchToHandler(BusyReq* r) {
	if (!ParsePath(r->Req))
		fprintf(Log, "[%5lld %5d] path parse failed: '%s'\n", (long long) r->ID, (int) r->Sock, r->Req->RawPath.c_str());

	if (!ParseQuery(r->Req))
		fprintf(Log, "[%5lld %5d] query parse failed: '%s'\n", (long long) r->ID, (int) r->Sock, r->Req->RawQuery.c_str());

	if (r->Req->IsWebSocketUpgrade())
		r->Req->WebSocketID = r->ID;

	// Call the user-provided handler
	Response w;
	Handler(w, *r->Req);

	if (w.Status == 0) {
		if (w.Body.size() == 0) {
			w.Status = Status500_Internal_Server_Error;
			w.SetHeader("Content-Type", "text/plain");
			w.Body = "Handler did not produce a response";
		} else {
			w.Status = Status200_OK;
		}
	}

	if (r->Req->IsWebSocketUpgrade() && w.Status == 200) {
		if (!UpgradeToWebSocket(w, r))
			return false;
		return true;
	}

	char linebuf[1024];
	if (w.FindHeader("Content-Length") == -1) {
		sprintf(linebuf, "%llu", (unsigned long long) w.Body.size());
		w.SetHeader("Content-Length", linebuf);
	}

	if (w.FindHeader("Date") == -1) {
		MakeDate(linebuf);
		w.SetHeader("Date", linebuf);
	}

	SendHeadBuf.resize(0);

	// top line
	sprintf(linebuf, "HTTP/1.1 %03u %s\r\n", (unsigned) w.Status, StatusMsg(w.Status));
	SendHeadBuf.append(linebuf);

	// other headers
	for (const auto& h : w.Headers) {
		SendHeadBuf.append(h.first);
		SendHeadBuf.append(": ");
		SendHeadBuf.append(h.second);
		SendHeadBuf.append("\r\n");
	}
	SendHeadBuf.append("\r\n");

	// Send head
	if (!SendBuffer(r, SendHeadBuf.c_str(), SendHeadBuf.size()))
		return false;

	// Send body
	if (!SendBuffer(r, w.Body.c_str(), w.Body.size()))
		return false;

	return true;
}

void Server::DispatchWebSocketFrame(BusyReq* r) {
	r->Req->WebSocketID = r->ID;
	switch (r->WebSockType) {
	case WebSocketFrameType::Binary: r->Req->Type = TypeWebSocketBinary; break;
	case WebSocketFrameType::Text: r->Req->Type = TypeWebSocketText; break;
	default:
		assert(false);
	}
	Response w;
	Handler(w, *r->Req);
	if (w.Body.size() != 0) {
		// Send back same type of frame that we received
		SendWebSocketInternal(r->ID, r->Req->Type, w.Body.c_str(), w.Body.size());
	}
}

bool Server::SendWebSocketInternal(int64_t websocketID, RequestType type, const void* buf, size_t len) {
	for (auto r : Requests) {
		if (r->ID == websocketID) {
			WebSocketFrameType ft = WebSocketFrameType::Unknown;
			switch (type) {
			case TypeWebSocketBinary: ft = WebSocketFrameType::Binary; break;
			case TypeWebSocketText: ft = WebSocketFrameType::Text; break;
			default:
				assert(false);
				return false;
			}

			byte  head[10];
			byte* h = head;
			*h++    = 0x80 | (byte) ft;
			if (len < 126) {
				*h++ = (byte) len;
			} else if (len < 65536) {
				*h++ = 126;
				*h++ = (byte)(len >> 8);
				*h++ = (byte) len;
			} else {
				*h++ = 127;
				*h++ = (byte)(len >> 56);
				*h++ = (byte)(len >> 48);
				*h++ = (byte)(len >> 40);
				*h++ = (byte)(len >> 32);
				*h++ = (byte)(len >> 24);
				*h++ = (byte)(len >> 16);
				*h++ = (byte)(len >> 8);
				*h++ = (byte) len;
			}

			if (!SendBuffer(r, (const char*) head, h - head)) {
				CloseRequest(r);
				return false;
			}

			if (!SendBuffer(r, (const char*) buf, len)) {
				CloseRequest(r);
				return false;
			}
			return true;
		}
	}
	return false;
}

bool Server::UpgradeToWebSocket(Response& w, BusyReq* r) {
	std::string   buf = r->Req->Header("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	unsigned char hash[20];
	phttp_sha1(hash, (const unsigned char*) buf.c_str(), (unsigned long) buf.size());
	char hashb64[29];
	Base64Encode(hash, sizeof(hash), hashb64);

	SendHeadBuf.resize(0);
	SendHeadBuf.append("HTTP/1.1 101 Switching Protocols\r\n");
	SendHeadBuf.append("Upgrade: websocket\r\n");
	SendHeadBuf.append("Connection: Upgrade\r\n");
	SendHeadBuf.append("Sec-WebSocket-Accept: ");
	SendHeadBuf.append(hashb64);
	SendHeadBuf.append("\r\n");
	for (const auto& h : w.Headers) {
		SendHeadBuf.append(h.first);
		SendHeadBuf.append(": ");
		SendHeadBuf.append(h.second);
		SendHeadBuf.append("\r\n");
	}
	SendHeadBuf.append("\r\n");

	if (!SendBuffer(r, SendHeadBuf.c_str(), SendHeadBuf.size()))
		return false;

	r->IsWebSocket = true;
	return true;
}

bool Server::SendBuffer(BusyReq* r, const char* buf, size_t len) {
	size_t sent = 0;
	while (sent != len) {
		if (StopSignal)
			return false;
		size_t trySend = std::min(len - sent, (size_t) 1048576);
		int    nsend   = send(r->Sock, buf + sent, (int) trySend, 0);
		if (nsend < 0) {
			fprintf(Log, "[%5lld %5d] send error %d %d\n", (long long) r->ID, (int) r->Sock, nsend, LastError());
			return false;
		} else if (nsend == 0) {
			fprintf(Log, "[%5lld %5d] socket closed on send\n", (long long) r->ID, (int) r->Sock);
			return false;
		}
		sent += nsend;
	}
	return true;
}

bool Server::SendWebSocketPong(BusyReq* r) {
	size_t pingSize = r->WebSockControlBody.size();
	if (pingSize > 125) {
		fprintf(Log, "[%5lld %5d] websocket pong larger than 125 bytes (%lld)\n", (long long) r->ID, (int) r->Sock, (long long) pingSize);
		return false;
	}

	// Assume that the PING did not fragment a request that was busy being sent

	uint8_t buf[2 + 125];
	buf[0] = 0x8a;
	buf[1] = (uint8_t) pingSize;
	memcpy(buf + 2, r->WebSockControlBody.c_str(), pingSize);
	return SendBuffer(r, (char*) buf, 2 + pingSize);
}

// returns -1 on error
inline char HexToInt(char h) {
	if (h >= 'a' && h <= 'f')
		return 10 + h - 'a';
	if (h >= 'A' && h <= 'F')
		return 10 + h - 'A';
	if (h >= '0' && h <= '9')
		return h - '0';
	return -1;
}

bool Server::ParsePath(Request* r) {
	const char* s   = r->RawPath.c_str();
	size_t      len = r->RawPath.size();
	for (size_t i = 0; i < len; i++) {
		char c = s[i];
		if (c == '%') {
			if (i >= len + 2)
				return false;
			c = (HexToInt(s[i + 1]) << 4) | HexToInt(s[i + 2]);
			i += 2;
		}
		r->Path += c;
	}
	return true;
}

bool Server::ParseQuery(Request* r) {
	using namespace std;
	enum { Key,
		   Value } state = Key;

	const char*          s   = r->RawQuery.c_str();
	size_t               len = r->RawQuery.size();
	pair<string, string> current;
	for (size_t i = 0; i < len; i++) {
		char c       = s[i];
		bool escaped = false;
		if (c == '%') {
			escaped = true;
			if (i >= len + 2)
				return false;
			c = (HexToInt(s[i + 1]) << 4) | HexToInt(s[i + 2]);
			i += 2;
		}

		if (!escaped && state == Key && c == '=') {
			state = Value;
			continue;
		} else if (!escaped && state == Value && c == '&') {
			r->Query.emplace_back(std::move(current));
			state = Key;
			continue;
		}

		if (state == Key)
			current.first += c;
		else
			current.second += c;
	}
	if (current.first.size() != 0 || current.second.size() != 0)
		r->Query.emplace_back(current);
	return true;
}

void Server::CloseRequest(BusyReq* r) {
	if (LogAllEvents)
		fprintf(Log, "[%5lld %5d] socket closing\n", (long long) r->ID, (int) r->Sock);

	size_t i = 0;
	for (; i < Requests.size(); i++) {
		if (Requests[i] == r)
			break;
	}
	assert(i != Requests.size());
	closesocket(r->Sock);
	Requests.erase(Requests.begin() + i);
	delete r->Req;
	delete (http_parser*) r->Parser;
	delete r;
}

void Server::Cleanup() {
	std::lock_guard<std::mutex> lock(BigLock);
	if (ListenSock != InvalidSocket) {
		int err = closesocket(ListenSock);
		if (err == ErrSOCKET_ERROR)
			fprintf(Log, "[%d] closesocket(ListenSock) failed: %d\n", (int) ListenSock, LastError());
		ListenSock = InvalidSocket;
	}

	for (size_t i = 0; i < Requests.size(); i++) {
		delete Requests[i]->Req;
		delete (http_parser*) Requests[i]->Parser;
		delete Requests[i];
	}
	Requests.clear();

	if (ClosePipe[0])
		close(ClosePipe[0]);
	if (ClosePipe[1])
		close(ClosePipe[1]);
	memset(ClosePipe, 0, sizeof(ClosePipe));

	free(Buf);
	Buf      = nullptr;
	BufCap   = 0;
	BufStart = nullptr;
	BufEnd   = nullptr;
}

void Server::cb_http_field(void* data, const char* field, size_t flen, const char* value, size_t vlen) {
	BusyReq* r = (BusyReq*) data;
	r->Req->Headers.push_back({std::string(field, flen), std::string(value, vlen)});

	if (flen == 14 && EqualsNoCase(field, "content-length", 14))
		r->Req->ContentLength = uatoi64(value, vlen);
}

void Server::cb_request_method(void* data, const char* at, size_t length) {
	BusyReq* r = (BusyReq*) data;
	r->Req->Method.assign(at, length);
}

void Server::cb_request_uri(void* data, const char* at, size_t length) {
	BusyReq* r = (BusyReq*) data;
	r->Req->URI.assign(at, length);
}

void Server::cb_fragment(void* data, const char* at, size_t length) {
	BusyReq* r = (BusyReq*) data;
	r->Req->Fragment.assign(at, length);
}

void Server::cb_request_path(void* data, const char* at, size_t length) {
	BusyReq* r = (BusyReq*) data;
	r->Req->RawPath.assign(at, length);
}

void Server::cb_query_string(void* data, const char* at, size_t length) {
	BusyReq* r = (BusyReq*) data;
	r->Req->RawQuery.assign(at, length);
}

void Server::cb_http_version(void* data, const char* at, size_t length) {
	BusyReq* r = (BusyReq*) data;
	r->Req->Version.assign(at, length);
}

void Server::cb_header_done(void* data, const char* at, size_t length) {
	BusyReq* r      = (BusyReq*) data;
	r->IsHeaderDone = true;
}

int Server::LastError() {
#ifdef _WIN32
	return (int) WSAGetLastError();
#else
    return errno;
#endif
}
} // namespace phttp

#ifdef _WIN32
#pragma warning(pop)
#endif
