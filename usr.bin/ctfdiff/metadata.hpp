#pragma once

#include <libelf.h>

#include "utility.hpp"
#include <string>
#include <string_view>

struct CtfMetaData {
    private:
	int data_fd;
	std::string filename;
	Elf *elf;

	bool from_elf_file();
	bool from_raw_file();

    public:
	Buffer ctfdata{};
	Buffer symdata{};
	Buffer strdata{};

	CtfMetaData(const std::string &filename);
	~CtfMetaData();

	std::string_view file_name() { return this->filename; }
	bool is_available();
};
