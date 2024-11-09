#include <sys/cdefs.h>
#include <sys/types.h>

#include "sys/bio.h"
#include "sys/ctf.h"
#include "sys/sx.h"
#include "sys/systm.h"

#include "ctfdata.hpp"
#include "ctftype.hpp"
#include "utility.hpp"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

bool
CtfTypeParser_V2::is_root() const
{
	return (CTF_V2_INFO_ISROOT(t.ctt_info));
}

int
CtfTypeParser_V2::kind() const
{
	return (CTF_V2_INFO_KIND(t.ctt_info));
}

ulong_t
CtfTypeParser_V2::vlen() const
{
	return (CTF_V2_INFO_VLEN(t.ctt_info));
}

uint_t
CtfTypeParser_V2::name() const
{
	return (t.ctt_name);
}

uint_t
CtfTypeParser_V2::type() const
{
	return (t.ctt_type);
}

size_t
CtfTypeParser_V2::increment() const
{
	if (t.ctt_size == CTF_V2_LSIZE_SENT) {
		return (sizeof(ctf_type_v2));
	} else {
		return (sizeof(ctf_stype_v2));
	}
}

size_t
CtfTypeParser_V2::size() const
{
	if (t.ctt_size == CTF_V2_LSIZE_SENT) {
		return (sizeof(ctf_type_v2));
	} else {
		return (sizeof(ctf_stype_v2));
	}
}

ArrayEntry
CtfTypeParser_V2::do_array(const std::byte *bytes) const
{
	const ctf_array_v2 *arr = reinterpret_cast<const ctf_array_v2 *>(bytes);
	return { arr->cta_contents, arr->cta_index, arr->cta_nelems };
}

std::pair<size_t, std::vector<MemberEntry>>
CtfTypeParser_V2::do_struct(const std::byte *bytes,
    const std::function<std::string_view(uint)> &get_str_by_ref) const
{
	std::vector<MemberEntry> res;
	int n = vlen(), i;
	size_t size;
	if (this->size() >= CTF_V2_LSTRUCT_THRESH) {
		const ctf_lmember_v2 *iter =
		    reinterpret_cast<const ctf_lmember_v2 *>(bytes);
		for (i = 0; i < n; ++i, ++iter)
			res.push_back({ get_str_by_ref(iter->ctlm_name),
			    iter->ctlm_type, CTF_LMEM_OFFSET(iter) });
		size = n * sizeof(struct ctf_lmember_v2);
	} else {
		const ctf_member_v2 *iter =
		    reinterpret_cast<const ctf_member_v2 *>(bytes);
		for (i = 0; i < n; ++i, ++iter)
			res.push_back({ get_str_by_ref(iter->ctm_name),
			    iter->ctm_type, iter->ctm_offset });
		size = n * sizeof(struct ctf_member_v2);
	}

	return { size, res };
}

CtfTypeParser *
CtfTypeParser_V2::create_symbol(const std::byte *data)
{
	CtfTypeParser_V2 *res = new CtfTypeParser_V2;
	memcpy(&res->t, data, sizeof(res->t));
	return (res);
}

bool
CtfTypeParser_V3::is_root() const
{
	return (CTF_V3_INFO_ISROOT(t.ctt_info));
}

int
CtfTypeParser_V3::kind() const
{
	return (CTF_V3_INFO_KIND(t.ctt_info));
}

ulong_t
CtfTypeParser_V3::vlen() const
{
	return (CTF_V3_INFO_VLEN(t.ctt_info));
}

uint_t
CtfTypeParser_V3::name() const
{
	return (t.ctt_name);
}

uint_t
CtfTypeParser_V3::type() const
{
	return (t.ctt_type);
}

size_t
CtfTypeParser_V3::increment() const
{
	if (t.ctt_size == CTF_V3_LSIZE_SENT) {
		return (sizeof(ctf_type_v3));
	} else {
		return (sizeof(ctf_stype_v3));
	}
}

size_t
CtfTypeParser_V3::size() const
{
	if (t.ctt_size == CTF_V3_LSIZE_SENT) {
		return (sizeof(ctf_type_v3));
	} else {
		return (sizeof(ctf_stype_v3));
	}
}

ArrayEntry
CtfTypeParser_V3::do_array(const std::byte *bytes) const
{
	const ctf_array_v3 *arr = reinterpret_cast<const ctf_array_v3 *>(bytes);
	return { arr->cta_contents, arr->cta_index, arr->cta_nelems };
}

std::pair<size_t, std::vector<MemberEntry>>
CtfTypeParser_V3::do_struct(const std::byte *bytes,
    const std::function<std::string_view(uint)> &get_str_by_ref) const
{
	std::vector<MemberEntry> res;
	int n = vlen(), i;
	size_t size;
	if (this->size() >= CTF_V3_LSTRUCT_THRESH) {
		const ctf_lmember_v3 *iter =
		    reinterpret_cast<const ctf_lmember_v3 *>(bytes);
		for (i = 0; i < n; ++i, ++iter)
			res.push_back({ get_str_by_ref(iter->ctlm_name),
			    iter->ctlm_type, CTF_LMEM_OFFSET(iter) });

		size = n * sizeof(ctf_lmember_v3);
	} else {
		const ctf_member_v3 *iter =
		    reinterpret_cast<const ctf_member_v3 *>(bytes);
		for (i = 0; i < n; ++i, ++iter)
			res.push_back({ get_str_by_ref(iter->ctm_name),
			    iter->ctm_type, iter->ctm_offset });

		size = n * sizeof(ctf_member_v3);
	}

	return { size, res };
}

CtfTypeParser *
CtfTypeParser_V3::create_symbol(const std::byte *data)
{
	CtfTypeParser_V3 *res = new CtfTypeParser_V3;
	memcpy(&res->t, data, sizeof(res->t));
	return (res);
}

bool
CtfType::compare(const CtfType &rhs,
    std::unordered_map<uint64_t, bool> &cache) const
{
	std::unordered_set<uint64_t> visited;

	return do_compare_child(*this, rhs, this->id, rhs.id, visited, cache);
}

bool
CtfType::do_compare(const CtfType &_lhs, const CtfType &_rhs,
    std::unordered_set<uint64_t> &visited,
    std::unordered_map<uint64_t, bool> &cache)
{
	const CtfType *lhs = &_lhs;
	const CtfType *rhs = &_rhs;

	auto ignored = [&](const auto &id) {
		return (std::find(ignore_ids.begin(), ignore_ids.end(), id) !=
		    ignore_ids.end());
	};

	/* we don't compare the type in ignore list */
	while (ignored(&typeid(*lhs))) {
		const CtfTypeQualifier *t =
		    dynamic_cast<const CtfTypeQualifier *>(lhs);
		lhs =
		    lhs->get_owned()->id_mapper().find(t->ref())->second.get();
	}

	while (ignored(&typeid(*rhs))) {
		const CtfTypeQualifier *t =
		    dynamic_cast<const CtfTypeQualifier *>(rhs);
		rhs =
		    rhs->get_owned()->id_mapper().find(t->ref())->second.get();
	}

	/* it guarentee all type should be same, so we can cast to specified
	 * cast in each do_compare_impl */
	if (typeid(*lhs) != typeid(*rhs))
		return (false);

	/* A type can be mutual refernce so that it will create a circle in the
	 * graph */

	uint64_t visited_pair = lhs->id << 31 | rhs->id;

	bool is_visited = visited.find(visited_pair) != visited.end();

	if (is_visited)
		return (true);

	if (cache.find(visited_pair) != cache.end())
		return (cache[visited_pair]);

	visited.insert(visited_pair);
	bool comp_res = (lhs->do_compare_impl(*rhs,
	    std::bind(CtfType::do_compare_child, std::placeholders::_1,
		std::placeholders::_2, std::placeholders::_3,
		std::placeholders::_4, std::ref(visited), std::ref(cache))));

	cache[visited_pair] = comp_res;
	visited.erase(visited_pair);

	return (comp_res);
}

bool
CtfType::do_compare_child(const CtfType &lhs, const CtfType &rhs,
    uint32_t l_child_id, uint32_t r_child_id,
    std::unordered_set<uint64_t> &visited,
    std::unordered_map<uint64_t, bool> &cache)
{
	auto &l_id_map = lhs.get_owned()->id_mapper();
	auto &r_id_map = rhs.get_owned()->id_mapper();
	auto l_child_iter = l_id_map.find(l_child_id);
	auto r_child_iter = r_id_map.find(r_child_id);

	/* In CTF, va_args record the ... as type 0, which is not contained in
	 * the id_table */
	if (l_child_iter == l_id_map.end() || r_child_iter == r_id_map.end())
		return (false);

	return do_compare(*(l_child_iter->second), *(r_child_iter->second),
	    visited, cache);
}

CtfType::~CtfType()
{
	delete this->parser;
}

uint32_t
CtfTypeInteger::encoding() const
{
	return (CTF_INT_ENCODING(this->data));
}

uint32_t
CtfTypeInteger::offset() const
{
	return (CTF_INT_OFFSET(this->data));
}

uint32_t
CtfTypeInteger::width() const
{
	return (CTF_INT_BITS(this->data));
}

uint32_t
CtfTypeFloat::encoding() const
{
	return (CTF_FP_ENCODING(this->data));
}

uint32_t
CtfTypeFloat::offset() const
{
	return (CTF_FP_OFFSET(this->data));
}

uint32_t
CtfTypeFloat::width() const
{
	return (CTF_FP_BITS(this->data));
}

bool
CtfTypeVaArg::do_compare_impl(const CtfType &rhs __unused,
    const CompareFunc &comp __unused) const
{
	return (true);
}

bool
CtfTypePrimitive::do_compare_impl(const CtfType &rhs,
    const CompareFunc &comp __unused) const
{
	const CtfTypePrimitive *d = dynamic_cast<const CtfTypePrimitive *>(
	    &rhs);
	return (this->data == d->data);
}

bool
CtfTypeArray::do_compare_impl(const CtfType &rhs, const CompareFunc &comp) const
{
	const CtfTypeArray *d = dynamic_cast<const CtfTypeArray *>(&rhs);
	const ArrayEntry &l_ent = this->entry, &r_ent = d->entry;

	return (l_ent.nelems == r_ent.nelems &&
	    comp(*this, rhs, l_ent.index, r_ent.index) &&
	    comp(*this, rhs, l_ent.contents, r_ent.contents));
}

bool
CtfTypeFunc::do_compare_impl(const CtfType &rhs, const CompareFunc &comp) const
{
	const CtfTypeFunc *d = dynamic_cast<const CtfTypeFunc *>(&rhs);

	if (this->args_vec.size() != d->args_vec.size())
		return (false);

	if (!comp(*this, rhs, this->ret_id, d->ret_id))
		return (false);

	int n = d->args_vec.size();

	for (int i = 0; i < n; ++i) {
		if (!comp(*this, rhs, this->args_vec[i], d->args_vec[i]))
			return (false);
	}

	return (true);
}

bool
CtfTypeEnum::do_compare_impl(const CtfType &rhs,
    const CompareFunc &comp __unused) const
{
	const CtfTypeEnum *d = dynamic_cast<const CtfTypeEnum *>(&rhs);

	if (this->members.size() != d->members.size())
		return (false);

	int n = d->members.size();

	for (int i = 0; i < n; ++i) {
		if (this->members[i].first != d->members[i].first ||
		    this->members[i].second != d->members[i].second)
			return (false);
	}

	return (true);
}

bool
CtfTypeForward::do_compare_impl(const CtfType &rhs,
    const CompareFunc &comp __unused) const
{
	return (this->name() == rhs.name());
}

bool
CtfTypeQualifier::do_compare_impl(const CtfType &rhs,
    const CompareFunc &comp) const
{
	const CtfTypeQualifier *d = dynamic_cast<const CtfTypeQualifier *>(
	    &rhs);

	return (comp(*this, rhs, this->ref_id, d->ref_id));
}

bool
CtfTypeUnknown::do_compare_impl(const CtfType &rhs __unused,
    const CompareFunc &comp __unused) const
{
	/* TODO: add unknown checker */
	return (false);
}

bool
CtfTypeStruct::do_compare_impl(const CtfType &rhs,
    const CompareFunc &comp) const
{
	const CtfTypeStruct *d = dynamic_cast<const CtfTypeStruct *>(&rhs);
	const auto &l_memb = this->args, &r_memb = d->args;

	if (this->size != d->size)
		return (false);

	if (l_memb.size() != r_memb.size())
		return (false);

	int n = l_memb.size(), i;

	for (i = 0; i < n; ++i) {
		if (l_memb[i].offset != r_memb[i].offset)
			return (false);

		if (!comp(*this, rhs, l_memb[i].type_id, r_memb[i].type_id))
			return (false);
	}

	return (true);
}

bool
CtfTypeUnion::do_compare_impl(const CtfType &rhs, const CompareFunc &comp) const
{
	const CtfTypeUnion *d = dynamic_cast<const CtfTypeUnion *>(&rhs);
	const auto &l_memb = this->args, &r_memb = d->args;

	if (this->size != d->size)
		return (false);

	if (l_memb.size() != r_memb.size())
		return (false);

	int n = l_memb.size(), i;

	for (i = 0; i < n; ++i) {
		if (l_memb[i].offset != r_memb[i].offset)
			return (false);

		if (!comp(*this, rhs, l_memb[i].type_id, r_memb[i].type_id))
			return (false);
	}

	return (true);
}
