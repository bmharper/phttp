#include "../phttp.h"
#include <string.h>
#include <string>
#include <thread>
#include "sema.h"

#ifndef _WIN32
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
	s.ListenAndRun(BindAddress, Port, [](phttp::Response& w, phttp::Request& r) {
		if (r.Path == "/") {
			w.SetStatusAndBody(200, "Hello");
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

void ProcessingThread(Queue* q, phttp::Server* s) {
	while (!s->StopSignal) {
		auto r = q->Pop();
		if (!r)
			break;

		phttp::Response w(r);
		if (r->Path == "/echo-method") {
			w.SetStatusAndBody(200, r->Method + "-MT-" + r->Body);
		} else {
			w.SetStatus(404);
		}
		s->SendHttp(w);
	}
}

int RunMultiThread(phttp::Server& s) {
	if (!s.Listen(BindAddress, Port)) {
		printf("Failed to listen\n");
		return 1;
	}

	int            nthread = 4;
	vector<thread> threads;
	Queue          q;
	for (int i = 0; i < nthread; i++) {
		threads.push_back(thread(ProcessingThread, &q, &s));
	}

	while (true) {
		auto queue = s.Recv();
		if (queue.size() == 0)
			break;
		for (auto r : queue) {
			if (r->IsHttp()) {
				q.Push(r);
			}
		}
	}

	// wake up the threads, and get them to exit
	for (int i = 0; i < nthread; i++)
		q.Push(nullptr);

	for (int i = 0; i < nthread; i++) {
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
