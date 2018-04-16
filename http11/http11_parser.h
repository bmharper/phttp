#pragma once
#ifndef phttp_http11_parser_h
#define phttp_http11_parser_h

#include "http11_common.h"

typedef struct phttp_parser {
	int    cs;
	size_t body_start;
	size_t content_len;
	size_t nread;
	size_t mark;
	size_t field_start;
	size_t field_len;
	size_t query_start;
	int    xml_sent;
	int    json_sent;

	void* data;

	phttp_field_cb   http_field;
	phttp_element_cb request_method;
	phttp_element_cb request_uri;
	phttp_element_cb fragment;
	phttp_element_cb request_path;
	phttp_element_cb query_string;
	phttp_element_cb http_version;
	phttp_element_cb header_done;

} phttp_parser;

#ifdef __cplusplus
extern "C" {
#endif
int    phttp_parser_init(phttp_parser* parser);
int    phttp_parser_finish(phttp_parser* parser);
size_t phttp_parser_execute(phttp_parser* parser, const char* data, size_t len, size_t off);
int    phttp_parser_has_error(phttp_parser* parser);
int    phttp_parser_is_finished(phttp_parser* parser);
#ifdef __cplusplus
}
#endif

#define phttp_parser_nread(parser) (parser)->nread

#endif
