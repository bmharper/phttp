#define _CRT_SECURE_NO_WARNINGS 1
#include "phttp.h"
#include <thread>
#include <string.h>

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#else
#include <signal.h>
#endif

static phttp::Server* SingleServer;

static const char* Script = R"(

var doHeavyFetch = false;
var doWebSocket = true;

if (doHeavyFetch) {
	// fetch heavy payload
	var r = new XMLHttpRequest();
	r.open('GET', '/heavy');
	r.send();
}

if (doWebSocket) {
	// open websocket
	var ws = new WebSocket("ws://localhost:8080");
	var tick = 0;

	var sendWS = function() {
		// stop if socket !open
		if (ws.readyState != 1)
			return;

		var msg = "Hello!";
		if (tick % 100 == 0) {
			for (var i = 0; i < 5000; i++) {
				msg += "very long message " + i + ", ";
			}
		} else if (tick % 20 == 0) {
			for (var i = 0; i < 100; i++) {
				msg += "long message " + i + ", ";
			}
		} else {
			msg = "Hello!" + tick;
			for (var i = 0; i < tick % 11; i++)
				msg += ".";
		}

		//var msg = "";
		//for (var i = 0; i < tick % 11; i++)
		//	msg += ".";

		console.log("sending..." + tick + ", " + ws.readyState);
		ws.send(msg);
		console.log("sent" + tick);
		
		tick++;
		setTimeout(function() {
			sendWS();
		}, 100);
	};

	ws.addEventListener('open', function() {
		sendWS();
	});

	ws.addEventListener('message', function(ev) {
		console.log("Server said: ", ev.data);
	});
}
)";

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
void sleepnano(int64_t nanoseconds) {
	timespec t;
	t.tv_nsec = nanoseconds % 1000000000;
	t.tv_sec  = (nanoseconds - t.tv_nsec) / 1000000000;
	nanosleep(&t, nullptr);
}
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif
	setup_ctrl_c_handler();

	phttp::Initialize();

	phttp::Server server;

	// We treat wsID as atomic here, mutating it from multiple threads. In production, use std::atomic<int64_t> instead.
	int64_t wsID = 0;

	std::thread wsSender([&wsID, &server] {
		// Wait until a web socket connection is made
		while (wsID == 0) {
			sleepnano(100 * 1000 * 1000);
			if (server.StopSignal)
				break;
		}

		// Here we send web socket messages from another thread.
		for (size_t i = 0; i < 100 && wsID != 0; i++) {
			char buf[100];
			sprintf(buf, "tick tock %d", (int) i);
			if (!server.SendWebSocket(wsID, phttp::RequestType::WebSocketText, buf, strlen(buf)))
				break;
			sleepnano(200 * 1000 * 1000);
		}
	});

	auto handler = [&server, &wsID](phttp::Response& w, phttp::Request& r) {
		if (r.IsWebSocketUpgrade()) {
			// Before deciding to return OK, you must validate the Origin header for CORS sake.
			// To upgrade the connection, send a 200, and populate the Sec-WebSocket-Protocol header,
			// making it one of the proposed protocols that the client requested.
			w.Status = 200;
			// assume client proposed only one protocol, and if so, reply that we're accepting it
			if (r.Header("Sec-WebSocket-Protocol") != "")
				w.SetHeader("Sec-WebSocket-Protocol", r.Header("Sec-WebSocket-Protocol"));
			wsID = r.ConnectionID;
			return;
		}

		if (r.Type == phttp::RequestType::Http) {
			if (r.Path == "/") {
				w.SetHeader("Content-Type", "text/html; charset=utf-8");
				w.SetHeader("Content-Encoding", "utf-8");
				w.Body = "<!DOCTYPE HTML>\n<head><link rel='stylesheet' href='a.css'></head>\n<body>Hello phttp!</body>\n";
				w.Body += "<script>";
				w.Body += Script;
				w.Body += "</script>";
			} else if (r.Path == "/a.css") {
				w.SetHeader("Content-Type", "text/css");
				w.Body = "body { color: #0a0 }";
			} else if (r.Path == "/heavy") {
				// Send 32 MB payload
				w.SetHeader("Content-Type", "text/plain");
				w.Body = "12345678901234567890123456789012"; // 32 bytes
				for (int i = 0; i < 20; i++)
					w.Body += w.Body;
			} else if (r.Path == "/seppuku") {
				w.Body += "Stopping server. The client may never receive this message\n";
				server.Stop();
			} else {
				w.Body += "Unknown path: " + r.Path + "\n";
				w.Body += "Query:\n";
				for (auto p : r.Query)
					w.Body += "" + p.first + ":" + p.second + "\n";
			}
		} else if (r.Type == phttp::RequestType::WebSocketClose) {
			printf("websocket closed by client\n");
			wsID = 0;
		} else if (r.Type == phttp::RequestType::WebSocketText) {
			// This demonstrates sending a reply to a websocket frame.
			// WebSockets are not typically used in a request/response manner,
			// but for the purposes of demonstration, we do that here.
			printf("websocket in: %s\n", r.Frame().c_str());
			server.SendWebSocket(r.ConnectionID, phttp::RequestType::WebSocketText, "hi from websocket!");
		}
	};

	server.LogAllEvents = true;
	SingleServer        = &server;
	server.ListenAndRun("127.0.0.1", 8080, handler);

	phttp::Shutdown();

	wsSender.join();

	SingleServer = nullptr;
	return 0;
}
