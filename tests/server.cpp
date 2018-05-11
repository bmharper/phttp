#define _CRT_SECURE_NO_WARNINGS 1
#include "../phttp.h"
#include <string.h>
#include <string>
#include <thread>
#include <atomic>
#include "sema.h"

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#else
#include <signal.h>
#endif

using namespace std;

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
			w.SetStatusAndBody(200, r.Body);
		} else if (r.Path == "/echo-method") {
			if (r.Method == "HEAD")
				w.SetStatusAndBody(200, "");
			else
				w.SetStatusAndBody(200, r.Method + "-" + r.Body);
		} else {
			w.SetStatus(404);
		}
	});
}

class Queue {
public:
	void Push(phttp::RequestPtr r) {
		{
			lock_guard<mutex> lock(Lock);
			Items.push_back(r);
		}
		Sem.signal();
	}

	phttp::RequestPtr Pop() {
		Sem.wait();
		lock_guard<mutex> lock(Lock);
		auto              item = Items.front();
		Items.erase(Items.begin());
		return item;
	}

private:
	mutex                     Lock;
	vector<phttp::RequestPtr> Items;
	Semaphore                 Sem;
};

struct ServerState {
	atomic<bool> Exit;
	Queue        Q;

	mutex                       WSLock;     // Guards access to all websocket state
	unordered_map<int64_t, int> WSLastRecv; // Key = websocket ID. Value = latest number received from client
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
	int               val = atoi(r->Body.c_str());
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

void ProcessingThread(ServerState* ss, phttp::Server* s) {
	while (!s->StopSignal) {
		auto r = ss->Q.Pop();
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
			w.SetStatusAndBody(200, r->Method + "-MT-" + r->Body);
			s->SendHttp(w);
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

	while (true) {
		auto queue = s.Recv();
		if (queue.size() == 0)
			break;
		for (auto r : queue)
			ss.Q.Push(r);
	}
	ss.Exit = true;

	// wake up the threads, and get them to exit
	for (int i = 0; i < threads.size(); i++)
		ss.Q.Push(nullptr);

	for (int i = 0; i < threads.size(); i++) {
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
	} else if (runMode == "--Concurrent") {
		return RunMultiThread(s);
	} else {
		printf("Unknown run mode %s\n", runMode.c_str());
		return 1;
	}
}
