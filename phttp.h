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
	Http,            // HTTP message
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

PHTTP_API bool Initialize();
PHTTP_API void Shutdown();

class PHTTP_API Request {
public:
	RequestType                                      Type          = RequestType::Http;
	size_t                                           ContentLength = 0; // Parsed from the Content-Length header
	int64_t                                          WebSocketID   = 0; // Only valid if this is a websocket, or if IsWebSocketUpgrade() is true
	std::string                                      Version;
	std::vector<std::pair<std::string, std::string>> Headers;
	std::string                                      Method;
	std::string                                      URI;
	std::string                                      RawPath; // Path before performing URL unescaping
	std::string                                      Path;    // Path with URL unescaping (ie %20 -> 32)
	std::string                                      Fragment;
	std::string                                      RawQuery;
	std::vector<std::pair<std::string, std::string>> Query; // Parse key+value pairs from QueryString
	std::string                                      Body;  // Body of HTTP or WebSocket request

	std::string Header(const char* h) const;       // Returns first header found, or empty string. Header name match is case-insensitive
	std::string QueryVal(const char* key) const;   // Returns first value found, or empty string
	int         QueryInt(const char* key) const;   // Returns first value found, or zero
	int64_t     QueryInt64(const char* key) const; // Returns first value found, or zero
	double      QueryDbl(const char* key) const;   // Returns first value found, or zero
	bool        IsWebSocketUpgrade() const;
	bool        IsHttp() const { return Type == RequestType::Http; }
	bool        IsWebSocketFrame() const { return Type == RequestType::WebSocketBinary || Type == RequestType::WebSocketText; }
	bool        IsWebSocketClose() const { return Type == RequestType::WebSocketClose; }
};

class PHTTP_API Response {
public:
	int                                              Status = 0;
	std::vector<std::pair<std::string, std::string>> Headers;
	std::string                                      Body;

	size_t FindHeader(const std::string& header) const; // Returns the index of the first named header, or -1 if not found. Search is case-insensitive
	void   SetHeader(const std::string& header, const std::string& val);
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

class PHTTP_API Server {
public:
#ifdef _WIN32
	typedef SOCKET        socket_t;
	static const socket_t InvalidSocket = INVALID_SOCKET;
#else
	typedef int           socket_t;
	static const socket_t InvalidSocket = (socket_t)(~0);
#endif

	int               MaxRequests  = 1024; // You can raise this to any arbitrary number, no phttp makes no performance guarantees about a large number of concurrent connections.
	LoggerPtr         Log          = nullptr;
	bool              LogAllEvents = false; // If enabled, all socket events are logged
	std::atomic<bool> StopSignal;

	Server();

	bool ListenAndRun(const char* bindAddress, int port, std::function<void(Response& w, Request& r)> handler);

	// Intended to be called from signal handlers, or another thread.
	// This sets StopSignal to true, and closes the listening socket
	void Stop();

	// Send a websocket frame. Can be called from multiple threads.
	// type must be Binary or Text
	// Returns false if the WebSocket channel is closed
	bool SendWebSocket(int64_t websocketID, RequestType type, const void* buf, size_t len);

private:
	// This represents a socket, which is initially opened for an HTTP request,
	// but may be recycled for future HTTP requests, or upgraded to a websocket.
	struct BusyReq {
		socket_t    Sock         = InvalidSocket;
		int64_t     ID           = 0; // ID of the channel
		void*       Parser       = nullptr;
		bool        IsHeaderDone = false;
		Request*    Req          = nullptr;
		std::string HttpHeadBuf; // Buffer of HTTP header

		// WebSocket state
		bool               IsWebSocket        = false;
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

		bool IsWebSockControlFrame() const { return !!((uint8_t) WebSockType & 8); }
	};

	// A websocket message that has been queued for sending
	struct WebSockOutMsg {
		int64_t     WebSocketID = 0;
		RequestType Type        = RequestType::WebSocketBinary;
		void*       Buf         = nullptr;
		size_t      Len         = 0;
	};

	std::mutex                                   BigLock; // Guards everything in here, except for StopSignal
	socket_t                                     ListenSock = InvalidSocket;
	int                                          ClosePipe[2]; // Used on linux to wake poll()
	std::function<void(Response& w, Request& r)> Handler;
	std::vector<BusyReq*>                        Requests;
	std::unordered_map<socket_t, BusyReq*>       Sock2Request; // Map from socket to request
	int64_t                                      NextReqID       = 1;
	int64_t                                      NextWebSocketID = 1;
	size_t                                       BufCap          = 0;       // Capacity of Buf
	uint8_t*                                     BufStart        = nullptr; // First byte in buffer
	uint8_t*                                     BufEnd          = nullptr; // One past last byte in buffer. Amount of data in Buf is BufEnd - BufStart.
	uint8_t*                                     Buf             = nullptr; // Buffer that is used for incoming data. Reset after every recv().
	std::string                                  SendHeadBuf;

	// Queue of websocket messages waiting to be sent.
	// Why do we need this? We need this because of our extremely simple BigLock, which is held while processing
	// incoming messages. It is a frequent use case to send a websocket message while processing an HTTP request,
	// or a websocket frame. However, during that processing, BigLock is held, so we would end up in a deadlock if
	// we tried to send the message immediately. Instead, we queue up that message, to be sent after processing
	// any incoming messages. It's unfortunate that we're adding this delay in sending, but right now it feels
	// like the simplest acceptable solution.
	// Note that there is one bug in this solution. When we go to sleep on poll(), in our main Run loop, we could
	// have items inside this queue. This wouldn't be sent until we got woken up. The correct solution is to
	// make our locking finer grained.
	std::mutex                 WebSocketOutQueueLock;
	std::vector<WebSockOutMsg> WebSocketOutQueue;

	void Run();
	void Cleanup();
	void Accept();
	void CloseRequest(BusyReq* r);
	// Generally, if a function returns false, then we must close the socket
	bool ReadFromRequest(BusyReq* r);
	bool ReadFromWebSocket(BusyReq* r);
	bool ReadFromWebSocketLoop(BusyReq* r);
	bool ReadFromHttpRequest(BusyReq* r);
	bool ReadWebSocketHead(BusyReq* r);
	bool DispatchToHandler(BusyReq* r);
	void DispatchWebSocketFrame(BusyReq* r);
	void DrainWebSocketOutQueue();
	bool SendWebSocketInternal(int64_t websocketID, RequestType type, const void* buf, size_t len); // Assumes BigLock is already held
	bool UpgradeToWebSocket(Response& w, BusyReq* r);
	void ReadWebSocketBody(BusyReq* r);
	bool SendBuffer(BusyReq* r, const char* buf, size_t len);
	bool SendWebSocketPong(BusyReq* r);
	bool ParsePath(Request* r);
	bool ParseQuery(Request* r);
	void WriteLog(const char* fmt, ...);

	size_t BufLen() const { return BufEnd - BufStart; }

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