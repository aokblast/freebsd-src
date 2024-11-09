#pragma once

#include <sys/types.h>

#include <gelf.h>
#include <stdint.h>

#include "ctf_headers.h"
#include "sys/ctf.h"

#include "ctftype.hpp"
#include "metadata.hpp"
#include <cstdint>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct CtfDiff;
struct CtfData;
struct CtfType;

using ShrCtfData = std::shared_ptr<CtfData>;
using ShrCtfType = std::shared_ptr<CtfType>;

struct CtfData {
    public:
	/* typedef */
	template <typename T> struct CtfObjEntry {
		using ty_type = T;
		std::string_view name; /* name of the variable */
		T type;		       /* type of the variable */
		uint32_t id;	       /* id of the variable */
	};

	using CtfFuncTypeEntry = CtfObjEntry<std::vector<ShrCtfType>>;
	using CtfFuncIdEntry = CtfObjEntry<std::vector<uint32_t>>;
	using CtfVarTypeEntry = CtfObjEntry<ShrCtfType>;
	using CtfVarIdEntry = CtfObjEntry<uint32_t>;

    private:
	/* members */
	CtfMetaData metadata;
	size_t ctf_id_width;
	ctf_header_t *header;
	std::unordered_map<uint32_t, ShrCtfType> id_to_types;
	std::vector<CtfVarIdEntry> static_variables;
	std::vector<CtfFuncIdEntry> functions;

	/* member function */
	CtfTypeFactory get_type_factory();
	bool zlib_decompress();

	std::string_view find_next_symbol_with_type(int &idx, uchar_t type);
	std::string_view get_str_from_ref(uint_t ref);
	bool ignore_symbol(GElf_Sym *sym, const char *name);

	std::pair<std::vector<CtfFuncTypeEntry>, std::vector<CtfFuncTypeEntry>>
	do_diff_func(const CtfData &rhs,
	    std::unordered_map<uint64_t, bool> &cache) const;
	std::pair<std::vector<CtfVarTypeEntry>, std::vector<CtfVarTypeEntry>>
	do_diff_var(const CtfData &rhs,
	    std::unordered_map<uint64_t, bool> &cache) const;
	CtfData(CtfMetaData &&metadata);

	/* static function */
	static bool do_parse_types(ShrCtfData info);
	static bool do_parse_data(ShrCtfData info);
	static bool do_parse_func(ShrCtfData info);

    public:
	std::pair<CtfDiff, CtfDiff> compare_and_get_diff(
	    const CtfData &rhs) const;

	bool is_available();
	inline const std::unordered_map<uint32_t, ShrCtfType> &id_mapper() const
	{
		return id_to_types;
	}

	static std::shared_ptr<CtfData> create_ctf_info(CtfMetaData &&metadata);
};

struct CtfDiff {
	std::vector<CtfData::CtfVarTypeEntry> variables;
	std::vector<CtfData::CtfFuncTypeEntry> functions;
};
