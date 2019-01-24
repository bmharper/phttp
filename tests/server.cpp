#define _CRT_SECURE_NO_WARNINGS 1
#include "../phttp.h"
#include <string.h>
#include <string>
#include <thread>
#include <atomic>
#include <algorithm>
#include "sema.h"

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#else
#include <signal.h>
#endif

using namespace std;
typedef uint8_t byte;

static const char*    BindAddress  = "localhost";
static int            Port         = 8080;
static phttp::Server* SingleServer = nullptr;

#ifdef _WIN32
BOOL ctrl_handler(DWORD ev) {
	if (ev == CTRL_C_EVENT && SingleServer != nullptr) {
		SingleServer->Stop();
		return TRUE;
	}
	return FALSE;
}
void setup_ctrl_c_handler() {
	SetConsoleCtrlHandler((PHANDLER_ROUTINE) ctrl_handler, TRUE);
}
void sleepnano(int64_t nanoseconds) {
	YieldProcessor();
	Sleep((DWORD)(nanoseconds / 1000000));
}
#else
void signal_handler(int sig) {
	if ((sig == SIGINT || sig == SIGQUIT || sig == SIGKILL) && SingleServer)
		SingleServer->Stop();
}
void setup_ctrl_c_handler() {
	struct sigaction sig;
	sig.sa_handler = signal_handler;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
	sigaction(SIGINT, &sig, nullptr);
}
void sleepnano(int64_t nanoseconds) {
	timespec t;
	t.tv_nsec = nanoseconds % 1000000000;
	t.tv_sec  = (nanoseconds - t.tv_nsec) / 1000000000;
	nanosleep(&t, nullptr);
}
#endif

void RunSingleThread(phttp::Server& s) {
	s.ListenAndRun(BindAddress, Port, [&s](phttp::Response& w, phttp::Request& r) {
		if (r.Path == "/") {
			w.SetStatusAndBody(200, "Hello");
		} else if (r.Path == "/kill") {
			w.SetStatus(200);
			s.Stop();
		} else if (r.Path == "/echo") {
			w.SetStatusAndBody(200, *r.HttpBody());
		} else if (r.Path == "/echo-method") {
			if (r.Method == "HEAD")
				w.SetStatusAndBody(200, "");
			else
				w.SetStatusAndBody(200, r.Method + "-" + *r.HttpBody());
		} else if (r.Path == "/digits") {
			int    ndigits = r.QueryInt("num");
			string body;
			for (int i = 0; i < ndigits; i++)
				body += '0' + (i % 10);
			w.SetStatusAndBody(200, body);
		} else {
			w.SetStatus(404);
		}
	});
}

template <typename T>
class Queue {
public:
	bool Blocking = true; // If Blocking is false, then Pop() returns T() if the queue is empty

	void Push(T r) {
		{
			lock_guard<mutex> lock(Lock);
			Items.push_back(r);
		}
		if (Blocking)
			Sem.signal();
	}

	T Pop() {
		if (Blocking)
			Sem.wait();
		lock_guard<mutex> lock(Lock);
		if (Items.size() == 0)
			return T();
		auto item = Items.front();
		Items.erase(Items.begin());
		return item;
	}

private:
	mutex     Lock;
	vector<T> Items;
	Semaphore Sem;
};

struct ServerState {
	atomic<bool>             Exit;
	Queue<phttp::RequestPtr> HttpQ;

	mutex                       WSLock;     // Guards access to all websocket state
	unordered_map<int64_t, int> WSLastRecv; // Key = websocket ID. Value = latest number received from client

	Queue<phttp::RequestPtr> StreamQ;

	ServerState() {
		HttpQ.Blocking   = true;
		StreamQ.Blocking = false;
	}
};

void Die(const char* fmt, ...) {
	printf("C++ failure: ");
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
	printf("\n\n");
	exit(1);
}

void ProcessWSFrame(ServerState* ss, phttp::RequestPtr r) {
	// Ensure that the value coming in is greater than the previous value that we received.
	// Also verify that the websocket ID is known to us
	lock_guard<mutex> lock(ss->WSLock);
	int               val = atoi(r->Frame().c_str());
	if (ss->WSLastRecv.find(r->ConnectionID) == ss->WSLastRecv.end()) {
		printf("Received value %d on unknown websocket id %d (occurs sometimes at start)", val, (int) r->ConnectionID);
		return;
	}

	int prev = ss->WSLastRecv[r->ConnectionID];
	if (val <= prev) {
		Die("Received invalid value %d on websocket id %d. Expected higher than %d", val, (int) r->ConnectionID, prev);
	} else {
		ss->WSLastRecv[r->ConnectionID] = val;
	}
}

void WebSocketPubThread(ServerState* ss, phttp::Server* s) {
	// This is a thread that just continually sends out websocket messages

	size_t rr           = 0; // round-robin counter
	size_t nFailedSends = 0;

	while (!ss->Exit) {
		int ms = 1000 * 1000;
		sleepnano(1 * ms);

		{
			lock_guard<mutex> lock(ss->WSLock);
			if (ss->WSLastRecv.size() != 0) {
				// round-robin through all of the active web sockets
				int64_t conID = 0;
				int     val   = 0;
				size_t  i     = 0;
				size_t  j     = rr % ss->WSLastRecv.size();
				for (auto p : ss->WSLastRecv) {
					if (i == j) {
						conID = p.first;
						val   = p.second;
						break;
					}
					i++;
				}
				rr++;
				char buf[20];
				sprintf(buf, "%d", val);
				//printf("Sent to websocket %d: %d\n", (int) conID, val);
				if (!s->SendWebSocket(conID, phttp::RequestType::WebSocketText, buf, strlen(buf))) {
					nFailedSends++;
					if (nFailedSends > 10)
						printf("%d failed sends: Sent to websocket %d, but it was already closed (expected to happen sometimes, but not often)\n", (int) nFailedSends, (int) conID);
				}
			}
		}
	}
}

// This demonstrates how to stream out a large download
void StreamThread(ServerState* ss, phttp::Server* s) {
	struct Stream {
		phttp::RequestPtr R;
		int64_t           Pos  = 0;
		int64_t           Size = 0;
		uint32_t          Val  = 0;
	};
	vector<Stream> streams;
	byte           buf[4000];
	uint32_t       mul = 997;

	while (!s->StopSignal) {
		auto newReq = ss->StreamQ.Pop();
		if (newReq) {
			Stream s;
			s.R    = newReq;
			s.Size = newReq->QueryInt64("bytes");
			streams.push_back(s);
		}
		for (size_t i = 0; i < streams.size(); i++) {
			auto&   s     = streams[i];
			int64_t nSend = min<int64_t>(s.Size - s.Pos, sizeof(buf));
			for (int64_t j = 0; j < nSend; j++) {
				s.Val  = (s.Val + 1) * mul;
				buf[j] = byte(s.Val & 0xff);
			}
		}
	}
}

void ProcessingThread(ServerState* ss, phttp::Server* s) {
	while (!s->StopSignal) {
		auto r = ss->HttpQ.Pop();
		if (!r) {
			// null request means quit
			break;
		}

		phttp::Response w(r);
		if (r->IsWebSocketUpgrade()) {
			//printf("Upgrade %d to WebSocket\n", (int) r->ConnectionID);
			w.Status = 200;
			// assume client proposed only one protocol, and if so, reply that we're accepting it
			if (r->Header("Sec-WebSocket-Protocol") != "")
				w.SetHeader("Sec-WebSocket-Protocol", r->Header("Sec-WebSocket-Protocol"));
			s->SendHttp(w);
			lock_guard<mutex> lock(ss->WSLock);
			ss->WSLastRecv.insert({r->ConnectionID, -1});
		} else if (r->IsWebSocketClose()) {
			lock_guard<mutex> lock(ss->WSLock);
			ss->WSLastRecv.erase(r->ConnectionID);
		} else if (r->IsWebSocketFrame()) {
			ProcessWSFrame(ss, r);
		} else if (r->Path == "/echo-method") {
			w.SetStatusAndBody(200, r->Method + "-MT-" + *r->HttpBody());
			s->SendHttp(w);
		} else if (r->Path == "/digits") {
			int    ndigits = r->QueryInt("num");
			string body;
			for (int i = 0; i < ndigits; i++)
				body += '0' + (i % 10);
			w.SetStatusAndBody(200, body);
			s->SendHttp(w);
		} else if (r->Path == "/stream") {
			int bytes = r->QueryInt64("bytes");
		} else if (r->Path == "/kill") {
			//printf("Received kill\n");
			w.SetStatus(200);
			s->SendHttp(w);
			s->Stop();
			//printf("Stopping\n");
		} else {
			w.SetStatus(404);
			s->SendHttp(w);
		}
	}
}

int RunMultiThread(phttp::Server& s) {
	if (!s.Listen(BindAddress, Port)) {
		printf("Failed to listen\n");
		return 1;
	}

	//s.LogAllEvents = true;

	int            nProcessingThreads = 2;
	vector<thread> threads;
	ServerState    ss;
	ss.Exit = false;
	for (int i = 0; i < nProcessingThreads; i++) {
		threads.push_back(thread(ProcessingThread, &ss, &s));
	}
	threads.push_back(thread(WebSocketPubThread, &ss, &s));
	threads.push_back(thread(StreamThread, &ss, &s));

	while (true) {
		auto queue = s.Recv();
		if (queue.size() == 0)
			break;
		for (auto r : queue)
			ss.HttpQ.Push(r);
	}
	ss.Exit = true;

	ss.StreamQ.Push(nullptr);

	// wake up the threads, and get them to exit
	for (size_t i = 0; i < threads.size(); i++)
		ss.HttpQ.Push(nullptr);

	for (size_t i = 0; i < threads.size(); i++) {
		threads[i].join();
	}

	return 0;
}

int main(int argc, char** argv) {
	phttp::Server s;
	SingleServer = &s;
	if (argc != 2) {
		printf("Must specify run mode such as --ListenAndRun");
		return 1;
	}
	string runMode = argv[1];

	bool enableLogs    = true;
	auto log           = std::make_shared<phttp::FileLogger>(enableLogs ? stdout : nullptr);
	s.LogInitialListen = false;
	s.Log              = log;
	//s.LogAllEvents  = true;

	phttp::Initialize();

	if (runMode == "--ListenAndRun") {
		RunSingleThread(s);
		return 0;
	} else if (runMode == "--concurrent") {
		return RunMultiThread(s);
	} else {
		printf("Unknown run mode %s\n", runMode.c_str());
		return 1;
	}
}
