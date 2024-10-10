#pragma once

#include "binary_extract.h"
#include "ctf_headers.h"


struct FunctionEntry { };

enum SymbolType {
	FUNC,
};


struct Symbol {
	enum SymbolType type;
	union {
		struct FunctionEntry f;
	} data;
};

void zlib_decompress_ctf(Ctf_Data *data, ctf_header_t *header);

