#include <stdint.h>
#include <stdio.h>
#include <algorithm>
#include <assert.h>
#include <time.h>
#include <string.h>
#include "phttp.h"
#include "sha1.h"

#ifdef _WIN32
#include <io.h>
#else
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#endif

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable : 4996) // sprintf
#endif

typedef unsigned char byte;
using namespace std;

namespace phttp {

#ifdef _WIN32
static const uint32_t Infinite        = INFINITE;
static const int      ErrSOCKET_ERROR = SOCKET_ERROR;
typedef LONG          nfds_t;

int poll(_Inout_ LPWSAPOLLFD fdArray, _In_ ULONG fds, _In_ INT timeout) {
	return WSAPoll(fdArray, fds, timeout);
}
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
	case Status429_Too_Many_Requests: return "Too Many Connections";
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

static int64_t atoi64(const char* s, size_t len) {
	int64_t v = 0;
	if (s[0] == '-') {
		for (size_t i = 1; i < len; i++)
			v = v * 10 - (s[i] - '0');
	} else {
		for (size_t i = 0; i < len; i++)
			v = v * 10 + (s[i] - '0');
	}
	return v;
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

Request::Request(phttp::Server* server, int64_t connectionID, RequestType type) : Server(server), ConnectionID(connectionID), Type(type) {
}

Request::~Request() {
	delete UserData;
}

std::string Request::Header(const char* h) const {
	for (const auto& p : Headers) {
		if (EqualsNoCase(p.first.c_str(), h))
			return p.second;
	}
	return "";
}

std::string Request::QueryVal(const char* key) const {
	for (const auto& p : Query) {
		if (p.first == key)
			return p.second;
	}
	return "";
}

int Request::QueryInt(const char* key) const {
	for (const auto& p : Query) {
		if (p.first == key)
			return atoi(p.second.c_str());
	}
	return 0;
}

int64_t Request::QueryInt64(const char* key) const {
	for (const auto& p : Query) {
		if (p.first == key)
			return atoi64(p.second.c_str(), p.second.size());
	}
	return 0;
}

double Request::QueryDbl(const char* key) const {
	for (const auto& p : Query) {
		if (p.first == key)
			return atof(p.second.c_str());
	}
	return 0;
}

size_t Request::ReadBody(size_t start, void* dst, size_t maxLen, bool clear) {
	lock_guard<mutex> lock(BodyLock);
	if (start >= Body.size())
		return 0;
	maxLen = std::min(Body.size() - start, maxLen);
	if (maxLen == 0)
		return 0;
	memcpy(dst, Body.data() + start, maxLen);
	if (clear)
		memmove((char*) Body.data() + start, Body.data() + start + maxLen, Body.size() - (start + maxLen));
	return maxLen;
}

size_t Request::ReadBody(size_t start, std::string& dst, size_t maxLen, bool clear) {
	lock_guard<mutex> lock(BodyLock);
	if (start >= Body.size())
		return 0;
	maxLen = std::min(Body.size() - start, maxLen);
	if (maxLen == 0)
		return 0;
	dst.append(Body.data() + start, maxLen);
	if (clear)
		memmove((char*) Body.data() + start, Body.data() + start + maxLen, Body.size() - (start + maxLen));
	return maxLen;
}

void Request::ClearBody() {
	lock_guard<mutex> lock(BodyLock);
	Body.resize(0);
}

void Request::WriteWebSocketBody(const void* buf, size_t len) {
	lock_guard<mutex> lock(BodyLock);
	Body.append((const char*) buf, len);
}

void Request::WriteHttpBody(const void* buf, size_t len, bool isLastHttpChunk) {
	lock_guard<mutex> lock(BodyLock);
	Body.append((const char*) buf, len);
	BodyWritten += len;
	if ((IsChunked && isLastHttpChunk) || (!IsChunked && BodyWritten == ContentLength))
		HttpBodyFinished = true;
}

size_t Request::BodyBytesReceived() {
	lock_guard<mutex> lock(BodyLock);
	return BodyWritten;
}

bool Request::IsHttpBodyFinished() {
	lock_guard<mutex> lock(BodyLock);
	return HttpBodyFinished;
}

const std::string* Request::HttpBody() {
	lock_guard<mutex> lock(BodyLock);
	if (!HttpBodyFinished)
		return nullptr;
	return &Body;
}

const std::string& Request::Frame() {
	if (Type != RequestType::WebSocketBinary && Type != RequestType::WebSocketText)
		return EmptyString;
	return Body;
}

bool Request::IsWebSocketUpgrade() const {
	// Chrome  (59) sends Connection: Upgrade
	// Firefox (53) sends Connection: keep-alive, Upgrade
	return IsHttp() &&
	       Header("Upgrade") == "websocket" &&
	       Header("Connection").find("Upgrade") != -1;
}

Response::Response() {
}

Response::Response(RequestPtr request) : Request(request) {
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

void Response::SetStatus(int status) {
	Status = status;
}

void Response::SetStatusAndBody(int status, const std::string& body) {
	Status = status;
	Body   = body;
}

void Response::Send() {
	Request->Server->SendHttp(*this);
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

// Returns true on success, or false if there was an error
static bool SetNonBlocking(Server::socket_t fd) {
	bool blocking = false;
#ifdef _WIN32
	unsigned long mode = blocking ? 0 : 1;
	return (ioctlsocket(fd, FIONBIO, &mode) == 0) ? true : false;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return false;
    flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    return (fcntl(fd, F_SETFL, flags) == 0) ? true : false;
#endif
}

Logger::~Logger() {
}

FileLogger::FileLogger(FILE* target) : Target(target) {
}

void FileLogger::Log(const char* msg) {
	if (!Target)
		return;
	fwrite(msg, strlen(msg), 1, Target);
	fwrite("\n", 1, 1, Target);
}

Server::Connection::Connection() {
	phttp_parser_init(&Parser);
	Parser.data           = this;
	Parser.http_field     = cb_http_field;
	Parser.request_method = cb_request_method;
	Parser.request_uri    = cb_request_uri;
	Parser.fragment       = cb_fragment;
	Parser.request_path   = cb_request_path;
	Parser.query_string   = cb_query_string;
	Parser.http_version   = cb_http_version;
	Parser.header_done    = cb_header_done;
}

Server::Server() {
	NextReqID = 1;
	memset(ClosePipe, 0, sizeof(ClosePipe));
}

bool Server::ListenAndRun(const char* bindAddress, int port, std::function<void(Response& w, Request& r)> handler) {
	if (!Listen(bindAddress, port))
		return false;
	while (!StopSignal) {
		vector<RequestPtr> requests = Recv();
		for (auto r : requests) {
			Response w(r);
			handler(w, *r);
			if (r->Type == RequestType::Http)
				SendHttp(w);
		}
	}
	Cleanup();
	return true;
}

bool Server::Listen(const char* bindAddress, int port) {
	NextReqID  = 1;
	StopSignal = false;
	if (!Log)
		Log = std::make_shared<FileLogger>(stdout);

	ListenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ListenSock == InvalidSocket) {
		WriteLog("socket() failed: %d", LastError());
		return false;
	}

#ifndef _WIN32
	// This avoids "socket already in use" errors when frequently restarting server on linux
	int optval = 1;
	setsockopt(ListenSock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	if (pipe(ClosePipe) == -1) {
		WriteLog("pipe() failed: %d", LastError());
		return false;
	}
#endif

	// This is necessary so that an accept() will never block. Were it not for this call, then
	// accept() could block, if the status of the listening socket had changed in between the time
	// when poll() woke us up, and the time that we called accept()
	if (!SetNonBlocking(ListenSock)) {
		WriteLog("Failed to set ListenSock to non-blocking mode: %d", LastError());
		return false;
	}

	sockaddr_in service = {0};
	service.sin_family  = AF_INET;
	inet_pton(AF_INET, bindAddress, &service.sin_addr);
	service.sin_port = htons(port);

	int err = ::bind(ListenSock, (sockaddr*) &service, sizeof(service));
	if (err == ErrSOCKET_ERROR) {
		WriteLog("bind() on %s:%d failed: %d", bindAddress, port, LastError());
		Cleanup();
		return false;
	}

	if (listen(ListenSock, SOMAXCONN) == ErrSOCKET_ERROR) {
		WriteLog("listen() on %s:%d failed: %d", bindAddress, port, LastError());
		Cleanup();
		return false;
	}

	if (LogInitialListen)
		WriteLog("Listening on port %d. ListenSocket = %d", (int) port, (int) ListenSock);

	if (RecvBuf == nullptr) {
		RecvBufCap = 16384;
		RecvBuf    = (uint8_t*) malloc(RecvBufCap);
		if (!RecvBuf) {
			WriteLog("Out of memory allocating %d bytes for RecvBuf", (int) RecvBufCap);
			return false;
		}
	}
	RecvBufStart = RecvBuf;
	RecvBufEnd   = RecvBuf;

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

std::vector<RequestPtr> Server::Recv() {
	std::vector<RequestPtr> requests;
	while (true) {
		vector<pollfd> fds;
		size_t         reqStart = 0;
		{
			lock_guard<mutex> lock(ConnectionsLock);
			fds.reserve(2 + Connections.size());

			// The code down below which does the Accept() assumes ListenSock is fds[0]
			fds.push_back({ListenSock, POLLIN, 0});
#ifndef _WIN32
			// On WIN32, we just close ListenSock, which is fine. Linux says that's illegal to do from a different thread, so we use a special pipe to wake us up on linux.
			fds.push_back({ClosePipe[0], POLLIN, 0});
#endif
			reqStart = fds.size();
			for (auto c : Connections)
				fds.push_back({c->Sock, POLLIN, 0});
		}

		//printf("poll in (%d)\n", (int) Connections.size());
		int n = poll(&fds[0], (nfds_t) fds.size(), -1);
		//printf("poll out\n");

		if (StopSignal)
			return {};
		if (n <= 0) {
			WriteLog("poll failed. errno: %v", errno);
			return {};
		}

		if (!!(fds[0].revents & POLLIN))
			AcceptOrReject();

		for (size_t i = reqStart; i < fds.size(); i++) {
			if (fds[i].revents == POLLNVAL) {
				WriteLog("Invalid poll() request on socket [%5d]", (int) fds[i].fd);
				continue;
			}
			if (fds[i].revents) {
				ConnectionPtr c;
				{
					lock_guard<mutex> lock(ConnectionsLock);
					auto              con = Sock2Connection.find(fds[i].fd);
					if (con == Sock2Connection.end()) {
						WriteLog("Received data on unknown socket [%5d]", (int) fds[i].fd);
						//char buf[1000];
						//int  nread = recv(fds[i].fd, buf, sizeof(buf), 0);
						//buf[nread] = 0;
						//printf("buf:\n%s\n", buf);
						continue;
					}
					c = con->second;
				}
				RequestPtr r;
				if (!ReadFromConnection(c.get(), r))
					CloseConnection(c);
				if (r != nullptr)
					requests.push_back(r);
			}
		}
		if (requests.size() != 0)
			return requests;
	}
	// unreachable
	return {};
}

void Server::AcceptOrReject() {
	bool haveCapacity = false;
	{
		lock_guard<mutex> lock(ConnectionsLock);
		haveCapacity = (int) Connections.size() < MaxConnections;
	}

	sockaddr_in addr;
	socklen_t   addr_len = sizeof(addr);
	socket_t    newSock  = accept(ListenSock, (sockaddr*) &addr, &addr_len);
	if (newSock == InvalidSocket) {
		WriteLog("accept() failed: %d", LastError());
		return;
	}
	if (!haveCapacity) {
		closesocket(newSock);
		return;
	}

	// Always enable NODELAY on our connections. We leave it up to the user to buffer up his
	// writes, so that they're sufficiently large. We make sure that we buffer up where we can.
	// On a spot test on my Ubuntu 16.04 machine, I saw a delay of 40ms with NODELAY switched off (the default setting).
	int optval = 1;
	setsockopt(newSock, IPPROTO_TCP, TCP_NODELAY, (const char*) &optval, sizeof(optval));

	ConnectionPtr con = make_shared<Connection>();
	con->Sock         = newSock;
	con->ID           = NextReqID++;
	con->Request      = make_shared<Request>(this, con->ID, RequestType::Http);
	{
		lock_guard<mutex> lock(ConnectionsLock);
		Connections.push_back(con);
		Sock2Connection.insert({newSock, con});
		ID2Connection.insert({con->ID, con});
	}
	if (LogAllEvents)
		WriteLog("[%5lld %5d] socked opened", (long long) con->ID, (int) con->Sock);
}

bool Server::ReadFromConnection(Connection* c, RequestPtr& r) {
	if (c->State == ConnectionState::HttpSend) {
		// We are not ready to receive a request. This is illegal (it is actually HTTP 1.1 "pipelining", but that never
		// came into use, and was replaced by HTTP/2).
		if (LogAllEvents)
			WriteLog("[%5lld %5d] socket recv while in HttpSend state", (long long) c->ID, (int) c->Sock);
		return false;
	}

	int nread = recv(c->Sock, (char*) RecvBuf, (int) RecvBufCap, 0);
	if (nread < 0) {
		WriteLog("[%5lld %5d] recv error %d %d. closing socket", (long long) c->ID, (int) c->Sock, nread, LastError());
		return false;
	} else if (nread == 0) {
		if (LogAllEvents)
			WriteLog("[%5lld %5d] socket closed on recv", (long long) c->ID, (int) c->Sock);
		return false;
	}

	//WriteLog("[%5lld %5d] read %d", (long long) c->ID, (int) c->Sock, nread);

	RecvBufStart = RecvBuf;
	RecvBufEnd   = RecvBuf + nread;

	bool ok;
	if (c->IsWebSocket())
		ok = ReadFromWebSocket(c, r);
	else
		ok = ReadFromHttpRequest(c, r);

	// Since every recv can be for a different request, we can't share the buffer between requests.
	RecvBufStart = RecvBuf;
	RecvBufEnd   = RecvBuf;

	return ok;
}

bool Server::ReadFromWebSocket(Connection* c, RequestPtr& r) {
	// Loop over websocket data until we can't make any further progress.
	// If there is any data left in the buffer, then it means that
	// we have an incomplete header. The maximum size of a header is 14
	// bytes, so if we haven't made progress, and we have 14 bytes or
	// more inside our buffer, then we have a bug.
	byte* prevBufStart = RecvBufStart - 1;
	while (RecvBufStart != prevBufStart) {
		prevBufStart = RecvBufStart;
		if (!ReadFromWebSocketLoop(c, r))
			return false;
	}
	// See comment above
	size_t len = RecvBufLen();
	assert(len < 14);

	if (len != 0) {
		// The buffer in 'RecvBuf' is shared by all connections, so we can't expect it to still be ours
		// when our next bytes come in on our TCP socket. So, if we were left with an incomplete header,
		// then we need to save those bytes for next time. This is a rare occurrence, so we don't mind
		// if it incurs some memmove penalties.
		memcpy(c->WebSockHeadBuf + c->WebSockHeadBufLen, RecvBufStart, RecvBufLen());
		c->WebSockHeadBufLen += RecvBufLen();
	}

	return true;
}

bool Server::ReadFromWebSocketLoop(Connection* c, RequestPtr& r) {
	if (!c->HaveWebSockHead) {
		if (!ReadWebSocketHead(c))
			return false;
	}
	if (!c->HaveWebSockHead)
		return true;

	ReadWebSocketBody(c);

	if (c->IsWebSockControlFrame()) {
		if (c->WebSockType == WebSocketFrameType::Close) {
			c->Request->Type = RequestType::WebSocketClose;
			r                = c->Request;
			// Send a reply Close frame, and then close our socket
			CloseWebSocket(c->ID, WebSocketCloseReason::Normal);
			// Returning false will cause us to exit out all the control flow paths. It will cause us to try and
			// close the socket twice, but not at the kernel level, just inside our own code, which is built to handle that.
			return false;
		}

		if (c->WebSockType == WebSocketFrameType::Ping) {
			if (!SendWebSocketPong(c))
				return false;
		}
	}

	if (c->WebSockPayloadRecv == c->WebSockPayloadLen) {
		// We could elect to dispatch continuation packets, but let's delay that until it's necessary. Could be an opt-in flag.
		if (c->IsWebSocketFin) {
			if (c->WebSockType == WebSocketFrameType::Binary || c->WebSockType == WebSocketFrameType::Text) {
				switch (c->WebSockType) {
				case WebSocketFrameType::Binary: c->Request->Type = RequestType::WebSocketBinary; break;
				case WebSocketFrameType::Text: c->Request->Type = RequestType::WebSocketText; break;
				default:
					assert(false);
				}
				// Return this request to the caller, and setup the connection to receive a new request
				r          = c->Request;
				c->Request = make_shared<Request>(this, c->ID, RequestType::Null);
			}
			c->Request->ClearBody();
		}
		// Reset to receive another frame
		c->HaveWebSockHead    = false;
		c->IsWebSocketFin     = false;
		c->WebSockPayloadRecv = 0;
		c->WebSockPayloadLen  = 0;
		c->WebSockType        = WebSocketFrameType::Unknown;
		c->WebSockMaskPos     = 0;
		c->WebSockControlBody.resize(0);
		memset(c->WebSockMask, 0, 4);
	}
	return true;
}

bool Server::ReadWebSocketHead(Connection* c) {
	// This function might run more than once. It is extremely unlikely in practice, but it certainly
	// is possible. For example, if the client sends us one byte at a time, then this function will enter
	// multiple times, each time getting a little bit further, but giving up several times, before
	// declaring HaveWebSockHead = true.
	// We know that this function has insufficient data if BufStart does not move forward.

	// If our previous recv() left us with an incomplete header, then we need to add those bytes back in here.
	// To simplify this code, we always work off a static buffer of 14 bytes.
	// Not all 14 bytes are necessarily populated.

	byte   buf[14];
	size_t extraBytes = std::min(RecvBufLen(), 14 - c->WebSockHeadBufLen);
	memcpy(buf, c->WebSockHeadBuf, c->WebSockHeadBufLen);
	memcpy(buf + c->WebSockHeadBufLen, RecvBufStart, extraBytes);
	size_t bufLen = c->WebSockHeadBufLen + extraBytes;

	// Need 2nd byte for payload len. The shortest header is 2 bytes. The longest header is 14 bytes.
	if (bufLen < 2)
		return true;

	c->IsWebSocketFin = !!(buf[0] & 128);
	c->WebSockType    = (WebSocketFrameType)(buf[0] & 15);

	byte len1 = buf[1];
	if (!(len1 & 128)) {
		WriteLog("[%5lld %5d] websocket client didn't mask request", (long long) c->ID, (int) c->Sock);
		return false;
	}
	c->WebSockPayloadLen = 0;
	len1 &= 127;
	size_t bytesOfLen = 0;
	if (len1 < 126) {
		// 7-bit length. 0..125
		c->WebSockPayloadLen = len1;
		bytesOfLen           = 1;
	} else if (len1 == 126 && bufLen >= 4) {
		// 16-bit length 126..65535
		c->WebSockPayloadLen = ((uint16_t) buf[2] << 8) | (uint16_t) buf[3];
		bytesOfLen           = 3;
	} else if (len1 == 127 && bufLen >= 10) {
		// 64-bit length 65536..LARGE
		c->WebSockPayloadLen = ((uint64_t) buf[2] << 56) |
		                       ((uint64_t) buf[3] << 48) |
		                       ((uint64_t) buf[4] << 40) |
		                       ((uint64_t) buf[5] << 32) |
		                       ((uint64_t) buf[6] << 24) |
		                       ((uint64_t) buf[7] << 16) |
		                       ((uint64_t) buf[8] << 8) |
		                       ((uint64_t) buf[9]);
		bytesOfLen = 9;
		//assert(c->WebSockPayloadLen < 1000000);
	}

	if (bytesOfLen == 0)
		return true;

	// We have the payload length, now we need the mask

	size_t headerSize = 1 + bytesOfLen + 4;
	bool   haveMask   = bufLen >= headerSize;

	if (!haveMask)
		return true;

	memcpy(c->WebSockMask, buf + 1 + bytesOfLen, 4);
	c->HaveWebSockHead = true;
	RecvBufStart += headerSize - c->WebSockHeadBufLen;
	c->WebSockHeadBufLen = 0;

	return true;
}

void Server::ReadWebSocketBody(Connection* c) {
	size_t nread = std::min<size_t>(RecvBufLen(), size_t(c->WebSockPayloadLen - c->WebSockPayloadRecv));

	_UnmaskBuffer(RecvBufStart, nread, c->WebSockMask, c->WebSockMaskPos);

	if (c->IsWebSockControlFrame())
		c->WebSockControlBody.append((char*) RecvBufStart, nread);
	else
		c->Request->WriteWebSocketBody(RecvBufStart, nread);

	c->WebSockPayloadRecv += nread;
	RecvBufStart += nread;
}

bool Server::ReadFromHttpRequest(Connection* c, RequestPtr& r) {
	auto parser            = &c->Parser;
	bool wasHttpHeaderDone = c->IsHttpHeaderDone;
	if (!c->IsHttpHeaderDone) {
		c->HttpHeadBuf.append((const char*) RecvBufStart, RecvBufLen());
		size_t oldPos = parser->nread;
		phttp_parser_execute(parser, c->HttpHeadBuf.c_str(), c->HttpHeadBuf.size(), parser->nread);
		RecvBufStart += parser->nread - oldPos;
		if (!!phttp_parser_has_error(parser)) {
			WriteLog("[%5lld %5d] http parser error", (long long) c->ID, (int) c->Sock);
			c->HttpHeadBuf.resize(0);
			return false;
		} else if (c->IsHttpHeaderDone) {
			c->HttpHeadBuf.resize(0);
		}
	}

	// We don't need to worry about only copying a limited amount of bytes here, or checking
	// whether the incoming bytes are for the next HTTP request, because we are HTTP 1.1,
	// so we're half duplex. All bytes that are coming in are for this one request.
	// The server will wait for a response before sending another request.
	// WebSockets are full duplex, which is why their implementation is more complex.

	// It is normal for IsHttpHeaderDone to be true now, even through it was false in the above block

	if (!wasHttpHeaderDone && c->IsHttpHeaderDone) {
		// HTTP request is ready to be consumed
		if (!ParsePath(c->Request.get()))
			WriteLog("[%5lld %5d] path parse failed: '%s'", (long long) c->ID, (int) c->Sock, c->Request->RawPath.c_str());

		if (!ParseQuery(c->Request.get()))
			WriteLog("[%5lld %5d] query parse failed: '%s'", (long long) c->ID, (int) c->Sock, c->Request->RawQuery.c_str());

		c->Request->IsChunked = c->Request->Header("Transfer-Encoding").find("chunked") != -1;
	}

	if (c->IsHttpHeaderDone) {
		if (c->Request->IsChunked) {
			if (!ReadHttpChunkedBody(c, RecvBufStart, RecvBufLen()))
				return false;
		} else {
			c->Request->WriteHttpBody(RecvBufStart, RecvBufLen(), false);
		}

		r = c->Request;
		if (c->Request->IsHttpBodyFinished())
			c->State = ConnectionState::HttpSend;
	}

	return true;
}

bool Server::ReadHttpChunkedBody(Connection* c, const void* _buf, size_t _len) {
	// As we consume '_buf', we increment 'buf', and decrement 'len'
	// Before returning from this function, we MUST consume all the bytes in 'buf'
	size_t      len = _len;
	const char* buf = (const char*) _buf;
	while (true) {
		if (HaveChunkHead(c)) {
			// We are busy reading a chunk. Continue doing so until we've read it all
			uint32_t chunkSize = 0;
			if (!ParseChunkHead(c, c->ChunkHead.c_str(), c->ChunkHead.size(), chunkSize))
				return false;
			size_t maxRead = min(len, chunkSize - c->ChunkReceived);
			c->Request->WriteHttpBody(buf, maxRead, chunkSize == 0);
			buf += maxRead;
			len -= maxRead;
			c->ChunkReceived += maxRead;
			if (c->ChunkReceived == chunkSize) {
				// reset for next chunk (this path is also triggered when we receive the final chunk)
				c->ChunkReceived = 0;
				c->ChunkHead.clear();
			}
		} else {
			// Consume 'buf' until we have a potentially valid chunk head
			while (len != 0 && !HaveChunkHead(c)) {
				c->ChunkHead += *buf;
				buf++;
				len--;
			}
			if (!HaveChunkHead(c) && c->ChunkHead.size() > 1024) {
				WriteLog("[%5lld %5d] Chunk head too long (max 1024 bytes)", (long long) c->ID, (int) c->Sock);
				return false;
			}
			if (!HaveChunkHead(c)) {
				// We have consumed 'buf' entirely, but still don't have a complete chunk head
				return true;
			}
		}
	}
	return true;
}

// Returns true if c->ChunkHead is at least 3 bytes, and ends with \r\n
bool Server::HaveChunkHead(Connection* c) {
	const std::string& head = c->ChunkHead;
	size_t             size = head.size();
	return size >= 3 && head[size - 2] == '\r' && head[size - 1] == '\n';
}

// This function assumes that 'buf' ends with \r\n
bool Server::ParseChunkHead(Connection* c, const char* buf, size_t len, uint32_t& chunkSize) {
	// HaveChunkHead() checks for this condition
	assert(len >= 3 && buf[len - 2] == '\r' && buf[len - 1] == '\n');

	uint64_t size64 = 0;
	for (size_t i = 0; i < len - 2; i++) {
		char     ch    = buf[i];
		uint64_t digit = 0;
		if (ch >= '0' && ch <= '9')
			digit = ch - '0';
		else if (ch >= 'a' && ch <= 'z')
			digit = ch - 'a';
		else if (ch >= 'A' && ch <= 'Z')
			digit = ch - 'A';
		else if (ch == ';')
			break;
		else {
			WriteLog("[%5lld %5d] Invalid character %d in chunk head (%.*s)", (long long) c->ID, (int) c->Sock, (int) ch, (int) len, buf);
			return false;
		}
		size64 = size64 * 16 + digit;
		if (size64 > (uint64_t) 4294967296) {
			WriteLog("[%5lld %5d] Chunk size too large (max 4294967296 bytes) (%.*s)", (long long) c->ID, (int) c->Sock, (int) len, buf);
			return false;
		}
	}

	chunkSize = (uint32_t) size64;
	return true;
}

void Server::SendHttp(Response& w) {
	if (!SendHttpInternal(w))
		CloseConnectionByID(w.Request->ConnectionID);
}

bool Server::SendHttpInternal(Response& w) {
	// This wouldn't be a constant if we supported chunked responses, or transmitting a response bit by bit.
	const bool isFinalResponse = true;

	if (w.Request->Method == "HEAD" && w.Body.size() != 0) {
		WriteLog("HEAD response may not contain a body");
		return false;
	}

	if (w.Status == 0) {
		if (w.Body.size() == 0) {
			w.Status = Status500_Internal_Server_Error;
			w.SetHeader("Content-Type", "text/plain");
			w.Body = "Handler did not produce a response";
		} else {
			w.Status = Status200_OK;
		}
	}

	ConnectionPtr c;
	{
		lock_guard<mutex> lock(ConnectionsLock);
		auto              pos = ID2Connection.find(w.Request->ConnectionID);
		if (pos == ID2Connection.end()) {
			// connection has been closed
			return true;
		}
		c = pos->second;
	}

	if (c->State != ConnectionState::HttpSend) {
		WriteLog("Attempt to send HTTP response when state is %d", (int) c->State);
		return false;
	}

	if (w.Request->IsWebSocketUpgrade() && w.Status == 200) {
		if (!UpgradeToWebSocket(w, c.get()))
			return false;
		return true;
	}

	string acceptEncoding = w.Request->Header("Accept-Encoding");
	char*  bodyBuf        = const_cast<char*>(w.Body.data());
	size_t bodyLen        = w.Body.size();
	bool   mustFreeBody   = false;

	if (Compressor && w.FindHeader("Content-Length") == -1 && w.FindHeader("Content-Encoding") == -1) {
		void*  cbuf = nullptr;
		size_t clen = 0;
		string responseEncoding;
		if (Compressor->Compress(acceptEncoding, w.Body.data(), w.Body.size(), cbuf, clen, responseEncoding)) {
			bodyBuf      = (char*) cbuf;
			bodyLen      = clen;
			mustFreeBody = true;
			w.SetHeader("Content-Encoding", responseEncoding);
		}
	}

	char linebuf[1024];
	if (w.FindHeader("Content-Length") == -1) {
		sprintf(linebuf, "%llu", (unsigned long long) bodyLen);
		w.SetHeader("Content-Length", linebuf);
	}

	if (w.FindHeader("Date") == -1) {
		MakeDate(linebuf);
		w.SetHeader("Date", linebuf);
	}

	// For HTTP/1.0, keep-alive is not the default
	bool keepAlive = true;
	if (c->Request->Version == "HTTP/1.0") {
		auto ch = c->Request->Header("Connection");
		if (ch.find("Keep-Alive") == -1 && ch.find("keep-alive") == -1)
			keepAlive = false;
	}

	if (w.FindHeader("Connection") == -1 && c->Request->Version == "HTTP/1.0" && keepAlive) {
		w.SetHeader("Connection", "Keep-Alive");
	}

	string wbuf;

	// top line
	sprintf(linebuf, "%s %03u %s\r\n", w.Request->Version.c_str(), (unsigned) w.Status, StatusMsg(w.Status));
	wbuf.append(linebuf);

	// other headers
	for (const auto& h : w.Headers) {
		wbuf.append(h.first);
		wbuf.append(": ");
		wbuf.append(h.second);
		wbuf.append("\r\n");
	}
	wbuf.append("\r\n");

	// If body is above a thumbsuck threshold, then send it separately.
	// We do this to avoid the expensive memcpy of a large response body.
	bool sendBodySeparate = bodyLen > 4000;
	if (!sendBodySeparate)
		wbuf.append(bodyBuf, bodyLen);

	if (isFinalResponse && keepAlive) {
		// Reset the parser for another request. It is important that we reset to allow new data BEFORE
		// sending the final bytes of the response. The moment we've sent those bytes, the client is allowed
		// to contact us on the socket with a new request, and if we didn't prepare the socket to receive
		// right here, then we'd have a race condition where the client could be requesting on the socket,
		// and we would not be ready to receive it.
		ResetForAnotherHttpRequest(c);
	}

	bool okSend1 = SendBytes(c.get(), wbuf.c_str(), wbuf.size());
	bool okSend2 = true;
	if (okSend1 && sendBodySeparate)
		okSend2 = SendBytes(c.get(), bodyBuf, bodyLen);

	if (mustFreeBody)
		Compressor->Free(acceptEncoding, bodyBuf);

	if (!(okSend1 && okSend2))
		return false;

	if (isFinalResponse && !keepAlive) {
		c->State = ConnectionState::Shutdown;
		shutdown(c->Sock, 2); // 2 = SHUT_RDWR(unix) = SD_BOTH(win32)
	}

	return true;
}

void Server::ResetForAnotherHttpRequest(ConnectionPtr c) {
	auto oldID          = c->ID;
	c->State            = ConnectionState::HttpRecv;
	c->ID               = NextReqID++;
	c->Request          = make_shared<Request>(this, c->ID, RequestType::Http);
	c->IsHttpHeaderDone = false;
	phttp_parser_init(&c->Parser);
	if (LogAllEvents)
		WriteLog("[%5lld %5d] recycling socket (ID %lld) for another request", (long long) c->ID, (int) c->Sock, (long long) oldID);
	{
		lock_guard<mutex> lock(ConnectionsLock);
		ID2Connection.erase(oldID);
		ID2Connection.insert({c->ID, c});
	}
}

bool Server::SendWebSocket(int64_t connectionID, RequestType type, const void* buf, size_t len) {
	auto c = ConnectionFromID(connectionID);
	if (c == nullptr)
		return false;

	WebSocketFrameType ft = WebSocketFrameType::Unknown;
	switch (type) {
	case RequestType::WebSocketBinary: ft = WebSocketFrameType::Binary; break;
	case RequestType::WebSocketText: ft = WebSocketFrameType::Text; break;
	case RequestType::WebSocketClose: ft = WebSocketFrameType::Close; break;
	default:
		assert(false);
		return true;
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
		uint64_t len64 = len;
		*h++           = 127;
		*h++           = (byte)(len64 >> 56);
		*h++           = (byte)(len64 >> 48);
		*h++           = (byte)(len64 >> 40);
		*h++           = (byte)(len64 >> 32);
		*h++           = (byte)(len64 >> 24);
		*h++           = (byte)(len64 >> 16);
		*h++           = (byte)(len64 >> 8);
		*h++           = (byte) len64;
	}

	string wbuf;
	wbuf.append((char*) head, h - head);
	wbuf.append((const char*) buf, len);

	if (!SendBytes(c.get(), wbuf.c_str(), wbuf.size())) {
		CloseConnection(c);
		return false;
	}

	if (type == RequestType::WebSocketClose) {
		// This is not strictly according to spec. According to spec, we should wait for the client to
		// send a close frame too, and only then do we close the TCP socket.
		CloseConnection(c);
	}

	return true;
}

bool Server::SendWebSocket(int64_t connectionID, RequestType type, const std::string& buf) {
	return SendWebSocket(connectionID, type, buf.c_str(), buf.size());
}

void Server::CloseWebSocket(int64_t connectionID, WebSocketCloseReason reason, const void* message, size_t messageLen) {
	byte     code[2];
	uint16_t r16 = (uint16_t) reason;
	code[0]      = (byte)(r16 >> 8);
	code[1]      = (byte)(r16);
	string wbuf;
	wbuf.append((const char*) code, 2);
	if (message)
		wbuf.append((const char*) message, messageLen);
	SendWebSocket(connectionID, RequestType::WebSocketClose, wbuf.c_str(), wbuf.size());
}

void Server::CloseWebSocket(int64_t connectionID, WebSocketCloseReason reason, const std::string& message) {
	bool haveMessage = message.size() != 0;
	CloseWebSocket(connectionID, reason, haveMessage ? message.c_str() : nullptr, haveMessage ? message.size() : 0);
}

void Server::_UnmaskBuffer(uint8_t* buf, size_t bufLen, uint8_t* mask, uint32_t& maskPos) {
	uint32_t mp = maskPos & 3;

	byte* bufEnd = buf + bufLen;

	// process until rbuf is 4 byte aligned
	for (; ((size_t) buf & 3) != 0 && buf < bufEnd; buf++, mp = (mp + 1) & 3)
		*buf ^= mask[mp];

	byte* bufEndDown4 = (byte*) (((size_t) bufEnd) & ~3);
	// unmask in 4 byte chunks
	uint32_t mask32 = 0;
	mask32          = (mask32 << 8) | mask[(mp + 3) & 3];
	mask32          = (mask32 << 8) | mask[(mp + 2) & 3];
	mask32          = (mask32 << 8) | mask[(mp + 1) & 3];
	mask32          = (mask32 << 8) | mask[mp & 3];
	for (; buf < bufEndDown4; buf += 4)
		*((uint32_t*) buf) ^= mask32;

	// process remaining 1, 2, or 3 bytes
	for (; buf < bufEnd; buf++, mp = (mp + 1) & 3)
		*buf ^= mask[mp];

	maskPos = mp;
}

bool Server::UpgradeToWebSocket(Response& w, Connection* c) {
	std::string   buf = w.Request->Header("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	unsigned char hash[20];
	phttp_sha1(hash, (const unsigned char*) buf.c_str(), (unsigned long) buf.size());
	char hashb64[29];
	Base64Encode(hash, sizeof(hash), hashb64);

	string wbuf;
	wbuf.resize(0);
	wbuf.append("HTTP/1.1 101 Switching Protocols\r\n");
	wbuf.append("Upgrade: websocket\r\n");
	wbuf.append("Connection: Upgrade\r\n");
	wbuf.append("Sec-WebSocket-Accept: ");
	wbuf.append(hashb64);
	wbuf.append("\r\n");
	for (const auto& h : w.Headers) {
		wbuf.append(h.first);
		wbuf.append(": ");
		wbuf.append(h.second);
		wbuf.append("\r\n");
	}
	wbuf.append("\r\n");

	if (!SendBytes(c, wbuf.c_str(), wbuf.size()))
		return false;

	c->State = ConnectionState::WebSocket;

	if (LogAllEvents)
		WriteLog("[%5lld %5d] upgraded to websocket", (long long) c->ID, (int) c->Sock);

	return true;
}

bool Server::SendBytes(Connection* c, const char* buf, size_t len) {
	std::lock_guard<std::mutex> lock(c->SendLock);
	size_t                      sent = 0;
	while (sent != len) {
		if (StopSignal)
			return false;
		size_t trySend = std::min(len - sent, (size_t) 1048576);
		int    nsend   = send(c->Sock, buf + sent, (int) trySend, 0);
		if (nsend < 0) {
			WriteLog("[%5lld %5d] send error %d %d", (long long) c->ID, (int) c->Sock, nsend, LastError());
			return false;
		} else if (nsend == 0) {
			WriteLog("[%5lld %5d] socket closed on send", (long long) c->ID, (int) c->Sock);
			return false;
		}
		sent += nsend;
	}
	return true;
}

bool Server::SendWebSocketPong(Connection* c) {
	size_t pingSize = c->WebSockControlBody.size();
	if (pingSize > 125) {
		WriteLog("[%5lld %5d] websocket pong larger than 125 bytes (%lld)", (long long) c->ID, (int) c->Sock, (long long) pingSize);
		return false;
	}

	uint8_t buf[2 + 125];
	buf[0] = 0x8a;
	buf[1] = (uint8_t) pingSize;
	memcpy(buf + 2, c->WebSockControlBody.c_str(), pingSize);
	return SendBytes(c, (char*) buf, 2 + pingSize);
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
		} else if (c == '+') {
			c = ' ';
		}
		r->Path += c;
	}
	return true;
}

bool Server::ParseQuery(Request* r) {
	using namespace std;
	enum {
		Key,
		Value,
	} state = Key;

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
		} else if (c == '+') {
			c = ' ';
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

void Server::WriteLog(const char* fmt, ...) {
	if (!Log)
		return;
	const size_t BSIZE = 1024;
	char         buf[BSIZE];
	va_list      va;
	va_start(va, fmt);
	int n = vsnprintf(buf, BSIZE, fmt, va);
	va_end(va);
	if (n < 0 || n >= BSIZE) {
		Log->Log("Log message truncated. Just emiting format string.");
		Log->Log(fmt);
		return;
	}
	buf[BSIZE - 1] = 0;
	Log->Log(buf);
}

Server::ConnectionPtr Server::ConnectionFromID(int64_t id) {
	lock_guard<mutex> lock(ConnectionsLock);
	auto              pos = ID2Connection.find(id);
	if (pos != ID2Connection.end())
		return pos->second;
	return nullptr;
}

void Server::CloseConnectionByID(int64_t id) {
	ConnectionPtr c = ConnectionFromID(id);
	if (c != nullptr)
		CloseConnection(c);
}

void Server::CloseConnection(ConnectionPtr c) {
	bool isWebSocket = c->IsWebSocket();
	{
		lock_guard<mutex> lock(ConnectionsLock);
		if (ID2Connection.find(c->ID) == ID2Connection.end()) {
			// connection has already been closed
			return;
		}
		size_t i = 0;
		for (; i < Connections.size(); i++) {
			if (Connections[i] == c)
				break;
		}
		closesocket(c->Sock);
		Sock2Connection.erase(c->Sock);
		ID2Connection.erase(c->ID);
		Connections.erase(Connections.begin() + i);
		c->Request = nullptr;
		c->State   = ConnectionState::Closed;
	}
	if (LogAllEvents)
		WriteLog("[%5lld %5d] socket closed", (long long) c->ID, (int) c->Sock);
	/*
	if (isWebSocket && Handler) {
		// Notify synchronous ListenAndRun handler that websocket is closed
		Request cr(c->ID);
		cr.Type = RequestType::WebSocketClose;
		Response w;
		Handler(w, cr);
		if (w.Body.size() != 0 || w.Status != 0)
			WriteLog("[%5lld %5d] attempt to send message in response to WebSocketClose", (long long) c->ID, (int) 0);
	}
	*/
}

void Server::Cleanup() {
	lock_guard<mutex> lock(ConnectionsLock);
	if (ListenSock != InvalidSocket) {
		int err = closesocket(ListenSock);
		if (err == ErrSOCKET_ERROR)
			WriteLog("[%d] closesocket(ListenSock) failed: %d", (int) ListenSock, LastError());
		ListenSock = InvalidSocket;
	}

	Connections.resize(0);
	Sock2Connection.clear();
	ID2Connection.clear();

	if (ClosePipe[0])
		close(ClosePipe[0]);
	if (ClosePipe[1])
		close(ClosePipe[1]);
	memset(ClosePipe, 0, sizeof(ClosePipe));

	free(RecvBuf);
	RecvBuf      = nullptr;
	RecvBufCap   = 0;
	RecvBufStart = nullptr;
	RecvBufEnd   = nullptr;
}

void Server::cb_http_field(void* data, const char* field, size_t flen, const char* value, size_t vlen) {
	Connection* c = (Connection*) data;
	c->Request->Headers.push_back({std::string(field, flen), std::string(value, vlen)});

	if (flen == 14 && EqualsNoCase(field, "content-length", 14)) {
		uint64_t clen = uatoi64(value, vlen);
		// what to do if ContentLength is greater than 4GB on 32-bit? I don't know.
		c->Request->ContentLength = (size_t) clen;
	}
}

void Server::cb_request_method(void* data, const char* at, size_t length) {
	Connection* c = (Connection*) data;
	c->Request->Method.assign(at, length);
}

void Server::cb_request_uri(void* data, const char* at, size_t length) {
	Connection* c = (Connection*) data;
	c->Request->URI.assign(at, length);
}

void Server::cb_fragment(void* data, const char* at, size_t length) {
	Connection* c = (Connection*) data;
	c->Request->Fragment.assign(at, length);
}

void Server::cb_request_path(void* data, const char* at, size_t length) {
	Connection* c = (Connection*) data;
	c->Request->RawPath.assign(at, length);
}

void Server::cb_query_string(void* data, const char* at, size_t length) {
	Connection* c = (Connection*) data;
	c->Request->RawQuery.assign(at, length);
}

void Server::cb_http_version(void* data, const char* at, size_t length) {
	Connection* c = (Connection*) data;
	c->Request->Version.assign(at, length);
}

void Server::cb_header_done(void* data, const char* at, size_t length) {
	Connection* c       = (Connection*) data;
	c->IsHttpHeaderDone = true;
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
