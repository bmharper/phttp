#pragma once
#ifndef PHTTP_H_INCLUDED
#define PHTTP_H_INCLUDED

// If exporting phttp from a Windows DLL, then
//   #define PHTTP_API __declspec(dllexport)
// and when importing,
//   #define PHTTP_API __declspec(dllimport)
#ifndef PHTTP_API
#define PHTTP_API
#endif

#include <atomic>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <string>
#include <functional>
#include <mutex>
#include <memory>
#include <stdio.h> // for FILE*

#ifdef _WIN32
#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <mstcpip.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdarg.h>
#include <unistd.h>
#endif

#include "http11/http11_parser.h"

namespace phttp {

enum StatusCode {
	Status100_Continue                        = 100,
	Status101_Switching_Protocols             = 101,
	Status102_Processing                      = 102,
	Status200_OK                              = 200,
	Status201_Created                         = 201,
	Status202_Accepted                        = 202,
	Status203_Non_Authoritative_Information   = 203,
	Status204_No_Content                      = 204,
	Status205_Reset_Content                   = 205,
	Status206_Partial_Content                 = 206,
	Status207_Multi_Status                    = 207,
	Status208_Already_Reported                = 208,
	Status226_IM_Used                         = 226,
	Status300_Multiple_Choices                = 300,
	Status301_Moved_Permanently               = 301,
	Status302_Found                           = 302,
	Status303_See_Other                       = 303,
	Status304_Not_Modified                    = 304,
	Status305_Use_Proxy                       = 305,
	Status307_Temporary_Redirect              = 307,
	Status308_Permanent_Redirect              = 308,
	Status400_Bad_Request                     = 400,
	Status401_Unauthorized                    = 401,
	Status402_Payment_Required                = 402,
	Status403_Forbidden                       = 403,
	Status404_Not_Found                       = 404,
	Status405_Method_Not_Allowed              = 405,
	Status406_Not_Acceptable                  = 406,
	Status407_Proxy_Authentication_Required   = 407,
	Status408_Request_Timeout                 = 408,
	Status409_Conflict                        = 409,
	Status410_Gone                            = 410,
	Status411_Length_Required                 = 411,
	Status412_Precondition_Failed             = 412,
	Status413_Payload_Too_Large               = 413,
	Status414_URI_Too_Long                    = 414,
	Status415_Unsupported_Media_Type          = 415,
	Status416_Range_Not_Satisfiable           = 416,
	Status417_Expectation_Failed              = 417,
	Status421_Misdirected_Request             = 421,
	Status422_Unprocessable_Entity            = 422,
	Status423_Locked                          = 423,
	Status424_Failed_Dependency               = 424,
	Status425_Unassigned                      = 425,
	Status426_Upgrade_Required                = 426,
	Status427_Unassigned                      = 427,
	Status428_Precondition_Required           = 428,
	Status429_Too_Many_Requests               = 429,
	Status430_Unassigned                      = 430,
	Status431_Request_Header_Fields_Too_Large = 431,
	Status500_Internal_Server_Error           = 500,
	Status501_Not_Implemented                 = 501,
	Status502_Bad_Gateway                     = 502,
	Status503_Service_Unavailable             = 503,
	Status504_Gateway_Timeout                 = 504,
	Status505_HTTP_Version_Not_Supported      = 505,
	Status506_Variant_Also_Negotiates         = 506,
	Status507_Insufficient_Storage            = 507,
	Status508_Loop_Detected                   = 508,
	Status509_Unassigned                      = 509,
	Status510_Not_Extended                    = 510,
	Status511_Network_Authentication_Required = 511,
};

enum class RequestType {
	Http,            // HTTP message (which can be a websocket upgrade)
	WebSocketBinary, // Binary WebSocket frame
	WebSocketText,   // Text WebSocket frame
	WebSocketClose,  // WebSocket is closing. You cannot send any response to this.
};

enum class WebSocketFrameType {
	Continuation = 0,
	Text         = 1,
	Binary       = 2,
	Close        = 8,
	Ping         = 9,
	Pong         = 10,
	Unknown      = 16,
};

// See https://tools.ietf.org/html/rfc6455#section-7.4
enum class WebSocketCloseReason {
	Normal             = 1000, // eg channel has no further purpose
	GoingAway          = 1001, // eg server is restarting
	ProtocolError      = 1002, // eg unexpected message
	UnableToHandleData = 1003, // eg image, when expecting text
	InvalidData        = 1007, // eg non-UTF8 data in text
	PolicyViolation    = 1008, // eg security violation
	InternalError      = 1011, // eg db read failure
};

PHTTP_API bool Initialize();
PHTTP_API void Shutdown();

/* A request, which is either an HTTP request, or an incoming WebSocket frame.
*/
class PHTTP_API Request {
public:
	RequestType                                      Type          = RequestType::Http;
	size_t                                           ContentLength = 0; // Parsed from the Content-Length header
	int64_t                                          ConnectionID  = 0; // ID of the socket connection (but not literally the socket fd).
	std::string                                      Version;
	std::vector<std::pair<std::string, std::string>> Headers;
	std::string                                      Method;
	std::string                                      URI;
	std::string                                      RawPath;  // Path before performing URL unescaping
	std::string                                      Path;     // Path with URL unescaping (ie %20 -> 32)
	std::string                                      Fragment; // The portion of the URL after the first #
	std::string                                      RawQuery; // The portion of the URL after the first ?
	std::vector<std::pair<std::string, std::string>> Query;    // Parsed key+value pairs from RawQuery
	std::string                                      Body;     // Body of HTTP request, or WebSocket frame

	Request(int64_t connectionID);
	std::string Header(const char* h) const;     // Returns first header found, or empty string. Header name match is case-insensitive
	std::string QueryVal(const char* key) const; // Returns first value found, or empty string
	int         QueryInt(const char* key) const; // Returns first value found, or zero
	double      QueryDbl(const char* key) const; // Returns first value found, or zero
	bool        IsWebSocketUpgrade() const;
	bool        IsHttp() const { return Type == RequestType::Http; }
	bool        IsWebSocketFrame() const { return Type == RequestType::WebSocketBinary || Type == RequestType::WebSocketText; }
	bool        IsWebSocketClose() const { return Type == RequestType::WebSocketClose; }
};

typedef std::shared_ptr<Request> RequestPtr;

/* A response to an HTTP request
*/
class PHTTP_API Response {
public:
	RequestPtr                                       Request; // The request that originated this response
	int                                              Status = 0;
	std::vector<std::pair<std::string, std::string>> Headers;
	std::string                                      Body;

	Response();
	Response(RequestPtr request);
	size_t FindHeader(const std::string& header) const; // Returns the index of the first named header, or -1 if not found. Search is case-insensitive
	void   SetHeader(const std::string& header, const std::string& val);
	void   SetStatus(int status);
	void   SetStatusAndBody(int status, const std::string& body);
};

// Logger interface
class PHTTP_API Logger {
public:
	virtual ~Logger();
	virtual void Log(const char* msg) = 0;
};

// Logger that logs to FILE*
class PHTTP_API FileLogger : public Logger {
public:
	FILE* Target = nullptr;

	FileLogger(FILE* target);
	void Log(const char* msg) override;
};

typedef std::shared_ptr<Logger> LoggerPtr;

/* phttp Server

Connection ID
-------------
The Connection ID is a 64-bit integer that serves two roles:
1. Normally, it represents a single HTTP request/response pair.
2. If we receive a WebSocket upgrade, then the ID remains the same for the duration
of that websocket's life.

*/
class PHTTP_API Server {
public:
#ifdef _WIN32
	typedef SOCKET        socket_t;
	static const socket_t InvalidSocket = INVALID_SOCKET;
#else
	typedef int           socket_t;
	static const socket_t InvalidSocket = (socket_t)(~0);
#endif

	int               MaxConnections   = 4096; // You can raise this to 64k, but phttp makes no performance guarantees
	LoggerPtr         Log              = nullptr;
	bool              LogAllEvents     = false; // If enabled, all socket events are logged
	bool              LogInitialListen = true;  // Log initial bind
	std::atomic<bool> StopSignal;               // Toggled by Stop()

	Server();

	// Listen and Recv until we get the stop signal.
	// This is the simplest way of using phttp, but it is limited,
	// because you can only process a single request as a time.
	bool ListenAndRun(const char* bindAddress, int port, std::function<void(Response& w, Request& r)> handler);

	// Start listening. Use in combination with Recv() to process incoming messages.
	// Returns false if unable to bind to the address:port
	bool Listen(const char* bindAddress, int port);

	// Intended to be called from signal handlers, or another thread.
	// This sets StopSignal to true, and closes the listening socket
	void Stop();

	// Wait for the next incoming message(s). This must only be called from a single thread,
	// which is typically the same thread that called Listen().
	// Returns an empty list if the stop signal has been received, or poll() returned
	// an error.
	std::vector<RequestPtr> Recv();

	// Send an HTTP response. This can be called from multiple threads.
	void SendHttp(Response& w);

	// Send a websocket frame. This can be called from multiple threads.
	// Returns false if the WebSocket channel has been closed
	bool SendWebSocket(int64_t connectionID, RequestType type, const void* buf, size_t len);

	// Close a websocket connection. This can be called from multiple threads.
	void CloseWebSocket(int64_t connectionID, WebSocketCloseReason reason, const void* message = nullptr, size_t messageLen = 0);

private:
	// The states that a Connection can be in
	enum class ConnectionState {
		HttpRecv,
		HttpSend,
		WebSocket,
		Shutdown,
		Closed,
	};
	// This represents a socket, which is initially opened for an HTTP request,
	// but may be recycled for future HTTP requests, or upgraded to a websocket.
	struct Connection {
		ConnectionState State = ConnectionState::HttpRecv;
		socket_t        Sock  = InvalidSocket;
		int64_t         ID    = 0;                // ID of the channel (see Server class docs)
		phttp_parser    Parser;                   // HTTP request parser state
		bool            IsHttpHeaderDone = false; // Toggled once Parser tells us that it's finished parsing the header
		RequestPtr      Request;                  // Associated request
		std::string     HttpHeadBuf;              // Buffer of HTTP header. The parser design needs to have the entire header in memory until it's finished.
		std::mutex      SendLock;                 // Used by the server to ensure that only a single thread is writing to the socket at a time

		// WebSocket state
		bool               HaveWebSockHead    = false;
		bool               IsWebSocketFin     = false; // FIN bit (ie final packet in a sequence. First frame can be final frame)
		uint64_t           WebSockPayloadRecv = 0;     // Number of payload bytes received in this websocket frame
		uint64_t           WebSockPayloadLen  = 0;     // Size of this frame's payload
		uint8_t            WebSockMask[4];
		uint32_t           WebSockMaskPos = 0;
		uint8_t            WebSockHeadBuf[14];    // In case we receive less than a full header, we need to save those few bytes for next time
		size_t             WebSockHeadBufLen = 0; // Number of bytes inside WebSockHeadBuf.
		WebSocketFrameType WebSockType       = WebSocketFrameType::Unknown;
		std::string        WebSockControlBody; // Buffer to store body of control frame (specifically Ping or Close). Regular frame's body is stored in Req->Body.

		Connection();
		bool IsWebSocket() const { return State == ConnectionState::WebSocket; }
		bool IsWebSockControlFrame() const { return !!((uint8_t) WebSockType & 8); }
	};

	typedef std::shared_ptr<Connection> ConnectionPtr;

	socket_t ListenSock = InvalidSocket;
	int      ClosePipe[2]; // Used on linux to wake poll()

	std::mutex                                  ConnectionsLock; // Guards Connections, Sock2Connection, NextReqID
	std::vector<ConnectionPtr>                  Connections;
	std::unordered_map<socket_t, ConnectionPtr> Sock2Connection; // Map from socket to connection. This changes only when we get a new TCP connection.
	std::unordered_map<int64_t, ConnectionPtr>  ID2Connection;   // Map from ID to connection. This changes frequently, as connections are recycled for new requests.

	std::atomic<int64_t> NextReqID; // Starts at 1

	// Buffer that is used by Recv()
	size_t   RecvBufCap   = 0;       // Capacity of RecvBuf
	uint8_t* RecvBufStart = nullptr; // First byte in buffer
	uint8_t* RecvBufEnd   = nullptr; // One past last byte in buffer. Amount of data in Buf is BufEnd - BufStart.
	uint8_t* RecvBuf      = nullptr; // Buffer that is used for incoming data. Reset after every recv().

	void          Cleanup();
	void          AcceptOrReject();
	ConnectionPtr ConnectionFromID(int64_t id);
	void          CloseConnection(ConnectionPtr c);
	void          CloseConnectionByID(int64_t id);
	void          ResetForAnotherHttpRequest(ConnectionPtr c);
	// Generally, if a function returns false, then we must close the socket
	bool ReadFromConnection(Connection* c, RequestPtr& r);
	bool ReadFromWebSocket(Connection* c, RequestPtr& r);
	bool ReadFromWebSocketLoop(Connection* c, RequestPtr& r);
	bool ReadFromHttpRequest(Connection* c, RequestPtr& r);
	bool ReadWebSocketHead(Connection* c);
	bool UpgradeToWebSocket(Response& w, Connection* c);
	void ReadWebSocketBody(Connection* c);
	bool SendHttpInternal(Response& w);
	bool SendBytes(Connection* c, const char* buf, size_t len);
	bool SendWebSocketPong(Connection* c);
	bool ParsePath(Request* r);
	bool ParseQuery(Request* r);
	void WriteLog(const char* fmt, ...);

	size_t RecvBufLen() const { return RecvBufEnd - RecvBufStart; }

	// http_parser callbacks
	static void cb_http_field(void* data, const char* field, size_t flen, const char* value, size_t vlen);
	static void cb_request_method(void* data, const char* at, size_t length);
	static void cb_request_uri(void* data, const char* at, size_t length);
	static void cb_fragment(void* data, const char* at, size_t length);
	static void cb_request_path(void* data, const char* at, size_t length);
	static void cb_query_string(void* data, const char* at, size_t length);
	static void cb_http_version(void* data, const char* at, size_t length);
	static void cb_header_done(void* data, const char* at, size_t length);

	static int LastError();
};

} // namespace phttp

#endif // PHTTP_H_INCLUDED