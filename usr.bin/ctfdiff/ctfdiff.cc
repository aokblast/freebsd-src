#include <getopt.h>
#include <libelf.h>

#include "sys/elf_common.h"

#include "ctfdata.hpp"
#include "metadata.hpp"
#include "utility.hpp"
#include <iostream>

static struct option longopts[] = {
	{ "f-ignore-const", no_argument, NULL, 'c' }, { NULL, 0, NULL, 0 }
};

static void
print_usage()
{
	std::cout << "ctfdiff compare the SUNW_ctf section of two ELF files\n";
	std::cout << "usage: ctfdiff <options> <file1> <file2>\n";
	std::cout << "options:\n";
	std::cout << "-f-ignore-const: ignore const decorator";
}

static void
do_compare_inplace(const CtfData &lhs, const CtfData &rhs)
{
	lhs.compare_and_get_diff(rhs);
}

int
main(int argc, char *argv[])
{
	char *l_filename = nullptr, *r_filename = nullptr;

	(void)elf_version(EV_CURRENT);
	int c = 0;

	if (argc < 0)
		exit(EXIT_FAILURE);

	for (opterr = 0; optind < argc; ++optind) {
		while ((c = getopt_long_only(argc, argv, "c", longopts,
			    NULL)) != (int)EOF) {
			switch (c) {
			case 'c':
				flags |= F_IGNORE_CONST;
				break;
			}
		}

		if (optind < argc) {
			if (l_filename != nullptr && r_filename != nullptr) {
				print_usage();
				return (0);
			} else if (l_filename == nullptr) {
				l_filename = argv[optind];
			} else {
				r_filename = argv[optind];
			}
		}
	}

	if (l_filename == nullptr || r_filename == nullptr) {
		print_usage();
		return (1);
	}

	CtfMetaData lhs(l_filename);

	if (!lhs.is_available()) {
		std::cout << "Cannot parse file " << argv[1] << '\n';
		return (1);
	}

	CtfMetaData rhs(r_filename);

	if (!rhs.is_available()) {
		std::cout << "Cannot parse file " << argv[1] << '\n';
		return (1);
	}

	auto l_info = CtfData::create_ctf_info(std::move(lhs));
	if (l_info == nullptr)
		return (1);

	auto r_info = CtfData::create_ctf_info(std::move(rhs));
	if (r_info == nullptr)
		return (1);

	if ((flags & F_IGNORE_CONST) != 0)
		ignore_ids.push_back(&typeid(CtfTypeConst));

	do_compare_inplace(*l_info.get(), *r_info.get());
}
