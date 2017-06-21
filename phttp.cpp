#include <stdint.h>
#include <stdio.h>
#include <algorithm>
#include <assert.h>
#include <time.h>
#include "phttp.h"
#include "http11/http11_parser.h"

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable : 4996) // sprintf
#endif

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

std::string Request::Header(const char* h) const {
	for (const auto& p : Headers) {
		if (EqualsNoCase(p.first.c_str(), h))
			return p.second;
	}
	return "";
}

void Response::SetHeader(const char* header, const char* val) {
	for (size_t i = 0; i < Headers.size(); i++) {
		if (Headers[i].first == header) {
			Headers[i].second = val;
			return;
		}
	}
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

	sockaddr_in service;
	service.sin_family = AF_INET;
	inet_pton(AF_INET, bindAddress, &service.sin_addr);
	service.sin_port = htons(port);

	int err = ::bind(ListenSock, (sockaddr*) &service, sizeof(service));
	if (err == ErrSOCKET_ERROR) {
		fprintf(Log, "bind() on %s:%d failed: %d\n", bindAddress, port, LastError());
		return false;
	}

	if (listen(ListenSock, SOMAXCONN) == ErrSOCKET_ERROR) {
		fprintf(Log, "listen() on %s:%d failed: %d\n", bindAddress, port, LastError());
		return false;
	}

	BufSize = 4096;
	Buf     = (char*) malloc(BufSize);
	if (!Buf)
		return false;

	fprintf(Log, "Listening on socket %d\n", (int) ListenSock);

	// Socket is ready to accept connections
	Run();
	Cleanup();

	return true;
}

void Server::Stop() {
	StopSignal = true;
}

void Server::Run() {
	while (!StopSignal) {
		fd_set   fds;
		socket_t maxSocket = ListenSock;
		FD_ZERO(&fds);
		FD_SET(ListenSock, &fds);
		for (auto r : Requests) {
			FD_SET(r->Sock, &fds);
			maxSocket = std::max(maxSocket, r->Sock);
		}
		timeval to;
		to.tv_sec  = 0;
		to.tv_usec = 1000 * 1000; // 1000 milliseconds
		int n      = select((int) (maxSocket + 1), &fds, nullptr, nullptr, &to);
		if (n <= 0)
			continue;

		// This is necesary on unix, because select() will abort on Ctrl+C, and then accept will block
		// [Check the above statement. It was written before changing the condition from (n == 0) to (n <= 0)]
		//if (StopSignal.load() != 0)
		//	break;

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
	}
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
	auto parser = (http_parser*) r->Parser;
	int  nread  = recv(r->Sock, (char*) Buf, (int) BufSize, 0);
	if (nread < 0) {
		fprintf(Log, "[%5lld %5d] recv error %d %d. closing socket\n", (long long) r->ID, (int) r->Sock, nread, LastError());
		return false;
	} else if (nread == 0) {
		if (LogAllEvents)
			fprintf(Log, "[%5lld %5d] socket closed on recv\n", (long long) r->ID, (int) r->Sock);
		return false;
	}

	size_t consumedByHeader = 0;
	if (!r->IsHeaderDone) {
		consumedByHeader = http_parser_execute(parser, (const char*) Buf, nread, parser->nread);
		if (!!http_parser_has_error(parser)) {
			fprintf(Log, "[%5lld %5d] http parser error\n", (long long) r->ID, (int) r->Sock);
			return false;
		}
	}
	// It is normal for IsHeaderDone to be true now, even through it was false in the above block
	if (r->IsHeaderDone) {
		size_t bodyLen = nread - consumedByHeader;
		if (bodyLen != 0)
			r->Req->Body.append(Buf + consumedByHeader, bodyLen);
	}

	bool ok = true;
	if (r->IsHeaderDone && r->Req->Body.size() == r->Req->ContentLength) {
		ok = DispatchToHandler(r);
		if (ok) {
			// Reset the parser for another request
			auto oldID      = r->ID;
			r->IsHeaderDone = false;
			auto parser     = (http_parser*) r->Parser;
			http_parser_init(parser);
			delete r->Req;
			r->Req = new Request();
			r->ID  = NextReqID++;
			if (LogAllEvents)
				fprintf(Log, "[%5lld %5d] recycling socket (ID %lld) for another request\n", (long long) r->ID, (int) r->Sock, oldID);
		}
	}

	return ok;
}

bool Server::DispatchToHandler(BusyReq* r) {
	if (!ParsePath(r->Req))
		fprintf(Log, "[%5lld %5d] path parse failed: '%s'\n", (long long) r->ID, (int) r->Sock, r->Req->RawPath.c_str());

	if (!ParseQuery(r->Req))
		fprintf(Log, "[%5lld %5d] query parse failed: '%s'\n", (long long) r->ID, (int) r->Sock, r->Req->RawQuery.c_str());

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

	char linebuf[4096];
	if (w.Body.size() != 0) {
		sprintf(linebuf, "%llu", (unsigned long long) w.Body.size());
		w.SetHeader("Content-Length", linebuf);
	}
	SendHeadBuf.resize(0);

	// top line
	sprintf(linebuf, "HTTP/1.1 %03u %s\r\n", (unsigned) w.Status, StatusMsg(w.Status));
	SendHeadBuf.append(linebuf);

	// date
	MakeDate(linebuf);
	SendHeadBuf.append("Date: ");
	SendHeadBuf.append(linebuf);
	SendHeadBuf.append("\r\n");

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
	if (ListenSock != InvalidSocket) {
		int err = closesocket(ListenSock);
		if (err == ErrSOCKET_ERROR)
			fprintf(Log, "[%d] closesocket(ListenSock) failed: %d\n", (int) ListenSock, LastError());
	}
	ListenSock = InvalidSocket;

	for (size_t i = 0; i < Requests.size(); i++) {
		delete Requests[i]->Req;
		delete (http_parser*) Requests[i]->Parser;
		delete Requests[i];
	}
	Requests.clear();

	free(Buf);
	Buf     = nullptr;
	BufSize = 0;
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
#ifdef HTTPBRIDGE_PLATFORM_WINDOWS
	return (int) WSAGetLastError();
#else
    return errno;
#endif
}
} // namespace phttp

#ifdef _WIN32
#pragma warning(pop)
#endif
