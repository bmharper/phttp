#include "phttp.h"

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#else
#include <signal.h>
#endif

static phttp::Server* SingleServer;

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
#else
void signal_handler(int sig) {
	if (SingleServer != nullptr)
		SingleServer->Stop();
}
void setup_ctrl_c_handler() {
	struct sigaction sig;
	sig.sa_handler = signal_handler;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
	sigaction(SIGINT, &sig, nullptr);
}
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif
	setup_ctrl_c_handler();

	phttp::Initialize();

	auto handler = [](phttp::Response& w, phttp::Request& r) {
		if (r.Path == "/") {
			w.SetHeader("Content-Type", "text/html");
			w.Body = "<!DOCTYPE HTML>\n<head><link rel='stylesheet' href='a.css'></head><body>Hello phttp!</body>";
			// fetch heavy payload
			w.Body += "<script>x = new XMLHttpRequest(); x.open('GET', '/heavy'); x.send();</script>";
		} else if (r.Path == "/a.css") {
			w.SetHeader("Content-Type", "text/css");
			w.Body = "body { color: #0a0 }";
		} else if (r.Path == "/heavy") {
			// Send 32 MB payload
			w.SetHeader("Content-Type", "text/plain");
			w.Body = "12345678901234567890123456789012"; // 32 bytes
			for (int i = 0; i < 20; i++)
				w.Body += w.Body;
		} else {
			w.Body += "Unknown path: " + r.Path + "\n";
			w.Body += "Query:\n";
			for (auto p : r.Query)
				w.Body += "" + p.first + ":" + p.second + "\n";
		}
	};

	phttp::Server server;
	server.LogAllEvents = true;
	SingleServer        = &server;
	server.ListenAndRun("127.0.0.1", 8080, handler);

	phttp::Shutdown();

	SingleServer = nullptr;
	return 0;
}
