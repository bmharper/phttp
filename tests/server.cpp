#include "../phttp.h"
#include <string.h>
#include <string>

#ifndef _WIN32
#include <signal.h>
#endif

using namespace std;

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

int main(int argc, char** argv) {
	phttp::Server s;
	SingleServer = &s;
	//s.LogAllEvents = true;
	if (argc != 2) {
		printf("Must specify run mode such as --ListenAndRun");
		return 1;
	}
	string runMode = argv[1];

	if (runMode == "--ListenAndRun") {
		s.ListenAndRun("localhost", 8080, [](phttp::Response& w, phttp::Request& r) {
			if (r.Path == "/") {
				w.SetStatusAndBody(200, "Hello");
			} else if (r.Path == "/echo") {
				w.SetStatusAndBody(200, r.Body);
			} else {
				w.SetStatus(404);
			}
		});
		return 0;
	} else {
		printf("Unknown run mode %s\n", runMode.c_str());
		return 1;
	}
}
