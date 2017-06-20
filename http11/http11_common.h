#ifndef _http11_common_h
#define _http11_common_h

#include <sys/types.h>

#ifdef _MSC_VER
#include <stddef.h> // MSVC 2013 defines size_t here
#endif

typedef void (*element_cb)(void *data, const char *at, size_t length);
typedef void (*field_cb)(void *data, const char *field, size_t flen, const char *value, size_t vlen);

#endif
