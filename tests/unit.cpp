#define _CRT_SECURE_NO_WARNINGS 1
#include "../phttp.h"
#include <assert.h>

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#endif

void TestUnmask() {
	int maskOffset = 10;
	for (int offset = 0; offset < maskOffset; offset++) {
		for (int len = 1; len < 30; len++) {
			for (uint32_t maskPos = 0; maskPos < 4; maskPos++) {
				uint8_t raw[100];
				uint8_t masked[100];
				uint8_t mask[4];
				for (int i = 0; i < 4; i++) {
					mask[i] = (uint8_t)((len + maskPos + i) * 73);
				}
				for (int i = 0; i < len + maskOffset; i++) {
					raw[i + offset]    = (uint8_t)(i * 98766797);
					masked[i + offset] = raw[i + offset] ^ mask[(i + maskPos) & 3];
				}
				uint32_t mp = maskPos;
				phttp::Server::_UnmaskBuffer(masked + offset, len, mask, mp);
				assert(mp == ((maskPos + len) & 3));
				assert(memcmp(raw + offset, masked + offset, len) == 0);
			}
		}
	}
}

int main(int argc, char** argv) {
	TestUnmask();
	return 0;
}
