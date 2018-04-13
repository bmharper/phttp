#include "../phttp.h"

int main(int argc, char** argv) {
	phttp::Server s;
	//s.LogAllEvents = true;
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
}