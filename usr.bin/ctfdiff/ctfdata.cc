
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>

#include <gelf.h>
#include <libelf.h>
#include <skein_port.h>
#include <stdint.h>
#include <strings.h>
#include <unistd.h>
#include <zconf.h>
#include <zlib.h>

#include "contrib/openzfs/lib/libspl/include/sys/stdtypes.h"
#include "ctf_headers.h"
#include "sys/ctf.h"
#include "sys/elf_common.h"

#include "ctfdata.hpp"
#include "ctftype.hpp"
#include "metadata.hpp"
#include "utility.hpp"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

bool
CtfData::is_available()
{
	return (this->header != nullptr);
}

bool
CtfData::ignore_symbol(GElf_Sym *sym, const char *name)
{
	u_char type = GELF_ST_TYPE(sym->st_info);

	/* when symbol is anomous or undefined */
	if (sym->st_shndx == SHN_UNDEF || sym->st_name == 0)
		return (true);

	if (strcmp(name, "_START_") == 0 || strcmp(name, "_END_") == 0)
		return (true);

	/* ignore address == 0 and abs) */
	if (type == STT_OBJECT && sym->st_shndx == SHN_ABS &&
	    sym->st_value == 0)
		return (true);

	return (false);
}

bool
CtfData::zlib_decompress()
{
	z_stream zs;
	std::byte *buffer;
	int rc;
	size_t buffer_size = header->cth_stroff + header->cth_strlen;

	buffer = new std::byte[buffer_size];

	bzero((void *)&zs, sizeof(zs));
	zs.next_in = reinterpret_cast<Bytef *>(metadata.ctfdata.data);
	zs.avail_in = metadata.ctfdata.size;
	zs.next_out = reinterpret_cast<Bytef *>(buffer);
	zs.avail_out = buffer_size;

	if ((rc = inflateInit(&zs)) != Z_OK) {
		std::cout << "failed to initialize zlib: " << zError(rc)
			  << '\n';
		return (false);
	}

	if ((rc = inflate(&zs, Z_FINISH)) != Z_STREAM_END) {
		std::cout << "failed to decompress CTF data: " << zError(rc)
			  << '\n';
		return (false);
	}

	if ((rc = inflateEnd(&zs)) != Z_OK) {
		std::cout << "failed to finish decompress: " << zError(rc)
			  << '\n';
		return (false);
	}

	if (zs.total_out != buffer_size) {
		std::cout << "CTF data is corrupted\n";
		return (false);
	}

	metadata.ctfdata.data = buffer;
	metadata.ctfdata.size = buffer_size;

	return (true);
}

CtfTypeFactory
CtfData::get_type_factory()
{
	return header->cth_version == CTF_VERSION_2 ?
	    &CtfTypeParser_V2::create_symbol :
	    &CtfTypeParser_V3::create_symbol;
}

CtfData::CtfData(CtfMetaData &&metadata)
    : metadata(metadata)
{
	Buffer &ctf_buffer = this->metadata.ctfdata;
	this->header = nullptr;

	if (ctf_buffer.size < sizeof(ctf_preamble_t)) {
		std::cout << metadata.file_name()
			  << " does not contain a CTF preamble\n";
		return;
	}

	const ctf_preamble_t *preamble = reinterpret_cast<ctf_preamble_t *>(
	    ctf_buffer.data);

	if (preamble->ctp_magic != CTF_MAGIC) {
		std::cout << metadata.file_name()
			  << " does not contain a valid ctf data\n";
		return;
	}

	if (preamble->ctp_version != CTF_VERSION_2 &&
	    preamble->ctp_version != CTF_VERSION_3) {
		std::cout << "CTF version " << preamble->ctp_version
			  << " is not available\n";
		return;
	}

	if (ctf_buffer.size < sizeof(ctf_header_t)) {
		std::cout << "File " << metadata.file_name()
			  << " contains invalid CTF header\n";
		return;
	}

	this->ctf_id_width = preamble->ctp_version == CTF_VERSION_2 ? 2 : 4;
	this->header = reinterpret_cast<ctf_header_t *>(ctf_buffer.data);
	ctf_buffer.data += sizeof(ctf_header_t);

	if (header->cth_flags & CTF_F_COMPRESS) {
		if (!zlib_decompress()) {
			this->header = nullptr;
			return;
		}
	}

	return;
}

std::shared_ptr<CtfData>
CtfData::create_ctf_info(CtfMetaData &&metadata)
{
	auto res = std::shared_ptr<CtfData>(
	    new CtfData(std::forward<CtfMetaData &&>(metadata)));

	if (!res->is_available()) {
		return nullptr;
	}

	do_parse_types(res);
	do_parse_data(res);
	do_parse_func(res);

	std::sort(res->functions.begin(), res->functions.end(),
	    [](const auto &lhs, const auto &rhs) {
		    return lhs.name < rhs.name;
	    });
	std::sort(res->static_variables.begin(), res->static_variables.end(),
	    [](const auto &lhs, const auto &rhs) {
		    return lhs.name < rhs.name;
	    });

	return (res);
}

std::string_view
CtfData::find_next_symbol_with_type(int &idx, uchar_t type)
{
	size_t i;
	uchar_t sym_type;
	GElf_Sym sym;
	const char *name;
	Elf_Data *sym_sec = metadata.symdata.elfdata;

	for (i = idx + 1; i < metadata.symdata.entries; ++i) {
		if (gelf_getsym(sym_sec, i, &sym) == 0)
			return ("");

		name = (const char *)(metadata.strdata.data + sym.st_name);
		sym_type = GELF_ST_TYPE(sym.st_info);

		if (type != sym_type || ignore_symbol(&sym, name))
			continue;
		idx = i;
		return (name);
	}

	return ("");
}

bool
CtfData::do_parse_data(ShrCtfData info)
{
	auto &header = info->header;
	auto &metadata = info->metadata;
	auto &static_variables = info->static_variables;
	auto ctf_id_width = info->ctf_id_width;

	const std::byte *iter = metadata.ctfdata.data + header->cth_objtoff;
	ulong_t n = (header->cth_funcoff - header->cth_objtoff) / ctf_id_width;

	int symidx, id;
	uint32_t type_id;
	std::string_view name;

	for (symidx = -1, id = 0; id < (int)n; ++id) {
		if (metadata.symdata.data != nullptr)
			name = info->find_next_symbol_with_type(symidx,
			    STT_OBJECT);
		else
			name = "";

		memcpy(&type_id, iter, ctf_id_width);
		iter += ctf_id_width;
		if (name != "")
			static_variables.push_back(
			    { name, type_id, static_cast<uint32_t>(id) });
	}

	return (true);
}

bool
CtfData::do_parse_types(ShrCtfData info)
{
	auto &header = info->header;
	auto &metadata = info->metadata;
	auto &id_to_types = info->id_to_types;
	const std::byte *iter = metadata.ctfdata.data + header->cth_typeoff;
	const std::byte *end = metadata.ctfdata.data + header->cth_stroff;
	auto ctf_id_width = info->ctf_id_width;
	uint64_t id;
	CtfTypeParser *(*type_factory)(const std::byte *);
	size_t vlen, increment;

	if (header->cth_typeoff & 3) {
		std::cout << "cth_typeoff is not aligned porperly\n";
		return (false);
	}

	if (header->cth_typeoff >= metadata.ctfdata.size) {
		std::cout << "file is truncated or cth_typeoff is corrupt\n";
		return (false);
	}

	if (header->cth_stroff >= metadata.ctfdata.size) {
		std::cout << "file is truncated or cth_stroff is corrupt\n";
		return (false);
	}

	if (header->cth_typeoff > header->cth_stroff) {
		std::cout << "file is corrupt -- cth_typeoff > cth_stroff\n";
		return (false);
	}

	uint32_t version = header->cth_version;
	id = 1;
	if (header->cth_parname)
		id += 1ul << (header->cth_version == CTF_VERSION_2 ?
			      CTF_V2_PARENT_SHIFT :
			      CTF_V3_PARENT_SHIFT);

	type_factory = info->get_type_factory();

	id_to_types[0] = std::make_shared<CtfTypeVaArg>(nullptr, 0, "va_arg",
	    info);

	for (/* */; iter < end; ++id) {
		CtfTypeParser *sym = type_factory(iter);
		vlen = 0;

		union {
			const std::byte *ptr;
			struct ctf_array_v2 *ap2;
			struct ctf_array_v3 *ap3;
			const struct ctf_member_v2 *mp2;
			const struct ctf_member_v3 *mp3;
			const struct ctf_lmember_v2 *lmp2;
			const struct ctf_lmember_v3 *lmp3;
			const ctf_enum_t *ep;
		} u;

		increment = sym->increment();
		u.ptr = iter + increment;

		switch (sym->kind()) {
		case CTF_K_INTEGER: {
			uint_t encoding = *(
			    reinterpret_cast<const uint_t *>(u.ptr));
			vlen = sizeof(uint32_t);
			id_to_types[id] =
			    std::make_shared<CtfTypeInteger>(encoding, sym, id,
				info->get_str_from_ref(sym->name()), info);
			break;
		}

		case CTF_K_FLOAT: {
			uint_t encoding = *(
			    reinterpret_cast<const uint_t *>(u.ptr));
			vlen = sizeof(uint32_t);
			id_to_types[id] =
			    std::make_shared<CtfTypeFloat>(encoding, sym, id,
				info->get_str_from_ref(sym->name()), info);
			break;
		}

		case CTF_K_POINTER: {
			uint_t type = sym->type();
			id_to_types[id] = std::make_shared<CtfTypePtr>(type,
			    sym, id, info->get_str_from_ref(sym->name()), info);
			break;
		}

		case CTF_K_ARRAY:
			id_to_types[id] = std::make_shared<CtfTypeArray>(u.ptr,
			    sym, id, info->get_str_from_ref(sym->name()), info);
			if (version == CTF_VERSION_2)
				vlen = sizeof(struct ctf_array_v2);
			else
				vlen = sizeof(struct ctf_array_v3);
			break;

		case CTF_K_FUNCTION: {
			uint_t ret = sym->type();
			uint_t arg = 0;
			int n = sym->vlen();
			std::vector<uint_t> args;

			for (int i = 0; i < n; ++i, u.ptr += ctf_id_width) {
				memcpy(&arg, u.ptr, ctf_id_width);
				args.push_back(arg);
			}

			id_to_types[id] = std::make_shared<CtfTypeFunc>(ret,
			    std::move(args), sym, id,
			    info->get_str_from_ref(sym->name()), info);
			vlen = roundup2(ctf_id_width * n, 4);
			break;
		}

		case CTF_K_STRUCT: {
			auto [size, members] = sym->do_struct(u.ptr,
			    std::bind(&CtfData::get_str_from_ref, info.get(),
				std::placeholders::_1));
			id_to_types[id] = std::make_shared<CtfTypeStruct>(
			    sym->size(), std::move(members), sym, id,
			    info->get_str_from_ref(sym->name()), info);
			vlen = size;
			break;
		}

		case CTF_K_UNION: {
			auto [size, members] = sym->do_struct(u.ptr,
			    std::bind(&CtfData::get_str_from_ref, info.get(),
				std::placeholders::_1));
			id_to_types[id] = std::make_shared<CtfTypeUnion>(
			    sym->size(), std::move(members), sym, id,
			    info->get_str_from_ref(sym->name()), info);
			vlen = size;
			break;
		}

		case CTF_K_ENUM: {
			std::vector<std::pair<std::string_view, uint32_t>> vec;
			int n = sym->vlen(), i;

			for (i = 0; i < n; ++i, u.ep++)
				vec.push_back(
				    { info->get_str_from_ref(u.ep->cte_name),
					u.ep->cte_value });

			id_to_types[id] =
			    std::make_shared<CtfTypeEnum>(std::move(vec), sym,
				id, info->get_str_from_ref(sym->name()), info);
			vlen = sizeof(ctf_enum_t) * n;
			break;
		}

		case CTF_K_FORWARD:
			id_to_types[id] = std::make_shared<CtfTypeForward>(sym,
			    id, info->get_str_from_ref(sym->name()), info);
			break;
		case CTF_K_TYPEDEF:
			id_to_types[id] =
			    std::make_shared<CtfTypeTypeDef>(sym->type(), sym,
				id, info->get_str_from_ref(sym->name()), info);
			break;
		case CTF_K_VOLATILE:
			id_to_types[id] =
			    std::make_shared<CtfTypeVolatile>(sym->type(), sym,
				id, info->get_str_from_ref(sym->name()), info);
			break;
		case CTF_K_CONST:
			id_to_types[id] =
			    std::make_shared<CtfTypeConst>(sym->type(), sym, id,
				info->get_str_from_ref(sym->name()), info);
			break;
		case CTF_K_RESTRICT:
			id_to_types[id] =
			    std::make_shared<CtfTypeRestrict>(sym->type(), sym,
				id, info->get_str_from_ref(sym->name()), info);
			break;
		case CTF_K_UNKNOWN:
			id_to_types[id] = std::make_shared<CtfTypeUnknown>(sym,
			    id, info);
			break;
		default:
			std::cout << "Unexpected kind: " << sym->kind() << '\n';
			return (false);
		}

		iter += increment + vlen;
	}

	return (true);
}

bool
CtfData::do_parse_func(ShrCtfData info)
{
	auto &header = info->header;
	auto &metadata = info->metadata;
	auto &functions = info->functions;
	auto ctf_id_width = info->ctf_id_width;

	const std::byte *iter = metadata.ctfdata.data + header->cth_funcoff;
	const std::byte *end = metadata.ctfdata.data + header->cth_typeoff;

	std::string_view name;

	int32_t id;
	int symidx;
	uint_t ctf_sym_info;

	for (symidx = -1, id = 0; iter < end; ++id) {
		memcpy(&ctf_sym_info, iter, ctf_id_width);
		iter += ctf_id_width;
		ushort_t kind = header->cth_version == CTF_VERSION_2 ?
		    CTF_V2_INFO_KIND(ctf_sym_info) :
		    CTF_V3_INFO_KIND(ctf_sym_info);
		ushort_t n = header->cth_version == CTF_VERSION_2 ?
		    CTF_V2_INFO_VLEN(ctf_sym_info) :
		    CTF_V3_INFO_VLEN(ctf_sym_info);

		uint_t i, arg;

		if (metadata.strdata.data != nullptr)
			name = info->find_next_symbol_with_type(symidx,
			    STT_FUNC);
		else
			name = "";

		if (kind == CTF_K_UNKNOWN && n == 0)
			continue; /* padding, skip it */

		if (kind != CTF_K_FUNCTION)
			std::cout << "incorrect type for function: " << name
				  << '\n';

		if (iter + n * ctf_id_width > end)
			std::cout << "function out of bound: " << name << '\n';

		if (name != "") {
			/* Return value */
			std::vector<uint_t> args;
			memcpy(&arg, iter, ctf_id_width);
			iter += ctf_id_width;
			args.push_back(arg);

			for (i = 0; i < n; ++i) {
				memcpy(&arg, iter, ctf_id_width);
				iter += ctf_id_width;
				args.push_back(arg);
			}

			functions.push_back({ name, std::move(args),
			    static_cast<uint32_t>(id) });
		} else
			iter += n * ctf_id_width + 1;
	}

	return (true);
}

std::string_view
CtfData::get_str_from_ref(uint_t ref)
{
	size_t offset = CTF_NAME_OFFSET(ref);

	const char *s = reinterpret_cast<const char *>(
	    metadata.ctfdata.data + header->cth_stroff + offset);

	if (CTF_NAME_STID(ref) != CTF_STRTAB_0)
		return ("<< ??? - name in external strtab >>");

	if (offset >= header->cth_strlen)
		return ("<< ??? - name exceeds strlab len >>");

	if (header->cth_stroff + offset >= metadata.ctfdata.size)
		return ("<< ??? - file truncated >>");

	if (s[0] == '\n')
		return ("(anon)");

	return (s);
}

#define L_DIFF 0
#define R_DIFF 1

template <typename Ret, typename T>
std::pair<std::vector<Ret>, std::vector<Ret>>
do_diff_generic(const std::vector<T> &lhs, const std::vector<T> &rhs,
    const std::function<bool(const typename Ret::ty_type &,
	const typename Ret::ty_type &)> &compare,
    const std::function<std::optional<typename Ret::ty_type>(
	const typename T::ty_type &, int LR)> &id_to_syms)
{
	size_t l_idx = 0, r_idx = 0;
	int name_diff;
	std::vector<Ret> l_diff, r_diff;

	while (l_idx < lhs.size() && r_idx < rhs.size()) {
		name_diff = lhs[l_idx].name.compare(rhs[r_idx].name);

		if (name_diff < 0) {
			auto syms = id_to_syms(lhs[l_idx].type, L_DIFF);
			if (syms != std::nullopt) {
				std::cout << "< [" << lhs[l_idx].id << "] "
					  << lhs[l_idx].name << '\n';
				l_diff.push_back(
				    { lhs[l_idx].name, *syms, lhs[l_idx].id });
			}
			++l_idx;
		} else if (name_diff > 0) {
			auto syms = id_to_syms(rhs[r_idx].type, R_DIFF);
			if (syms != std::nullopt) {
				std::cout << "> [" << rhs[r_idx].id << "] "
					  << rhs[r_idx].name << '\n';
				r_diff.push_back(
				    { rhs[r_idx].name, *syms, rhs[r_idx].id });
			}
			++r_idx;
		} else {
			auto l_syms = id_to_syms(lhs[l_idx].type, L_DIFF);
			auto r_syms = id_to_syms(rhs[r_idx].type, R_DIFF);
			bool sym_diff = true;

			/*
			 * TODO: elaborate on detailed compare diff for each
			 * type
			 */
			if (l_syms != std::nullopt && r_syms != std::nullopt) {
				sym_diff = !compare(*l_syms, *r_syms);
			}

			if (sym_diff) {
				if (l_syms != std::nullopt) {
					std::cout << "< [" << lhs[l_idx].id
						  << "] " << lhs[l_idx].name
						  << '\n';

					l_diff.push_back({ lhs[l_idx].name,
					    *l_syms, lhs[l_idx].id });
				}
				if (r_syms != std::nullopt) {
					std::cout << "> [" << rhs[r_idx].id
						  << "] " << rhs[r_idx].name
						  << '\n';
					r_diff.push_back({ rhs[r_idx].name,
					    *r_syms, rhs[r_idx].id });
				}
			}
			++l_idx;
			++r_idx;
		}
	}

	while (l_idx < lhs.size()) {
		auto syms = id_to_syms(lhs[l_idx].type, L_DIFF);
		if (syms != std::nullopt) {
			std::cout << "< [" << lhs[l_idx].id << "] "
				  << lhs[l_idx].name << '\n';
			l_diff.push_back(
			    { lhs[l_idx].name, *syms, lhs[l_idx].id });
		}
		++l_idx;
	}

	while (l_idx < lhs.size()) {
		auto syms = id_to_syms(rhs[r_idx].type, R_DIFF);
		if (syms != std::nullopt) {
			std::cout << "< [" << rhs[r_idx].id << "] "
				  << rhs[r_idx].name << '\n';

			r_diff.push_back(
			    { rhs[r_idx].name, *syms, rhs[r_idx].id });
		}
		++r_idx;
	}

	return (std::make_pair(l_diff, r_diff));
}

std::pair<std::vector<CtfData::CtfFuncTypeEntry>,
    std::vector<CtfData::CtfFuncTypeEntry>>
CtfData::do_diff_func(const CtfData &rhs,
    std::unordered_map<uint64_t, bool> &cache) const
{
	const auto &lhs = *this;

	auto get_symbol =
	    [&](const std::vector<uint32_t> &ids,
		int LR) -> std::optional<std::vector<ShrCtfType>> {
		std::vector<ShrCtfType> res;
		const std::unordered_map<uint32_t, ShrCtfType> *converter;

		switch (LR) {
		case L_DIFF:
			converter = &(lhs.id_to_types);
			break;
		case R_DIFF:
			converter = &(rhs.id_to_types);
			break;
		}

		for (const auto id : ids) {
			auto iter = converter->find(id);
			if (iter == converter->end())
				return (std::nullopt);
			res.push_back(iter->second);
		}

		return (std::make_optional(res));
	};

	auto compare = [&](const std::vector<ShrCtfType> &lhs,
			   const std::vector<ShrCtfType> &rhs) {
		size_t idx = 0;

		if (lhs.size() != rhs.size())
			return (false);

		for (; idx < lhs.size(); ++idx) {
			if (!lhs[idx]->compare(*rhs[idx], cache))
				return (false);
		}

		return (true);
	};

	return do_diff_generic<CtfFuncTypeEntry, CtfFuncIdEntry>(
	    this->functions, rhs.functions, compare, get_symbol);
}

std::pair<std::vector<CtfData::CtfVarTypeEntry>,
    std::vector<CtfData::CtfVarTypeEntry>>
CtfData::do_diff_var(const CtfData &rhs,
    std::unordered_map<uint64_t, bool> &cache) const
{
	const auto &lhs = *this;

	auto get_symbol = [&](const uint32_t &id,
			      int LR) -> std::optional<ShrCtfType> {
		ShrCtfType res;
		const std::unordered_map<uint32_t, ShrCtfType> *converter;

		switch (LR) {
		case L_DIFF:
			converter = &(lhs.id_to_types);
			break;
		case R_DIFF:
			converter = &(rhs.id_to_types);
			break;
		}

		auto iter = converter->find(id);
		if (iter == converter->end())
			return (std::nullopt);
		res = iter->second;

		return (std::make_optional(res));
	};

	auto compare = [&](const ShrCtfType &lhs, const ShrCtfType &rhs) {
		if (!lhs->compare(*rhs, cache))
			return (false);

		return (true);
	};

	return do_diff_generic<CtfVarTypeEntry, CtfVarIdEntry>(
	    this->static_variables, rhs.static_variables, compare, get_symbol);
}

/*
 * cache work as following:
 * id_pair = lhs.id << 31 | rhs.id
 * if id_pair found in map, means two types have compared
 * return the result directly, compare it vice versa
 */
std::pair<CtfDiff, CtfDiff>
CtfData::compare_and_get_diff(const CtfData &rhs) const
{
	std::unordered_map<uint64_t, bool> cache;
	auto [l_diff_funcs, r_diff_funcs] = this->do_diff_func(rhs, cache);
	auto [l_diff_syms, r_diff_syms] = this->do_diff_var(rhs, cache);

	return std::make_pair(CtfDiff { l_diff_syms, l_diff_funcs },
	    CtfDiff { r_diff_syms, r_diff_funcs });
}
