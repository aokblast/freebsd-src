#pragma once

#include <libelf.h>

#include <cstddef>
#include <typeinfo>
#include <vector>

extern int flags;
extern std::vector<const std::type_info *> ignore_ids;

enum CtfFlag {
	F_IGNORE_CONST = 1,
};

struct Buffer {
	std::byte *data;
	size_t size;
	size_t entries;
	Elf_Data *elfdata;

	Buffer(std::byte *data, size_t size)
	    : data(data)
	    , size(size)
	    , entries(0)
	    , elfdata(nullptr) {};
	Buffer(std::byte *data, size_t size, size_t entries)
	    : data(data)
	    , size(size)
	    , entries(entries)
	    , elfdata(nullptr) {};

	Buffer() = default;
};
