#pragma once

#include <sys/cdefs.h>

#include "ctf_headers.h"
#include "sys/ctf.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

struct CtfDiff;
struct CtfData;

using ShrCtfData = std::shared_ptr<CtfData>;

struct ArrayEntry {
	uint32_t contents, index, nelems;
};

struct MemberEntry {
	std::string_view name; /* name of the member */
	uint32_t type_id;      /* type ref of the member */
	uint64_t offset;       /* offset in the member */
};

struct CtfTypeParser {
	/* virtual function */
	virtual ~CtfTypeParser() = default;
	virtual bool is_root() const = 0;
	virtual int kind() const = 0;
	virtual ulong_t vlen() const = 0;
	virtual uint_t name() const = 0;
	virtual uint_t type() const = 0;
	virtual size_t increment() const = 0;
	virtual size_t size() const = 0;
	virtual ArrayEntry do_array(const std::byte *bytes) const = 0;
	virtual std::pair<size_t, std::vector<MemberEntry>>
	do_struct(const std::byte *,
	    const std::function<std::string_view(uint)> &) const = 0;
};

struct CtfTypeParser_V2 : CtfTypeParser {
    private:
	struct ctf_type_v2 t;

    public:
	/* virtual function */
	virtual bool is_root() const override;
	virtual int kind() const override;
	virtual ulong_t vlen() const override;
	virtual uint_t name() const override;
	virtual uint_t type() const override;
	virtual size_t increment() const override;
	virtual size_t size() const override;
	virtual ArrayEntry do_array(const std::byte *bytes) const override;
	virtual std::pair<size_t, std::vector<MemberEntry>>
	do_struct(const std::byte *,
	    const std::function<std::string_view(uint)> &) const override;

	/* static function */
	static CtfTypeParser *create_symbol(const std::byte *data);
};

struct CtfTypeParser_V3 : CtfTypeParser {
    private:
	struct ctf_type_v3 t;

    public:
	/* virtual function */
	virtual bool is_root() const override;
	virtual int kind() const override;
	virtual ulong_t vlen() const override;
	virtual uint_t name() const override;
	virtual uint_t type() const override;
	virtual size_t increment() const override;
	virtual size_t size() const override;
	virtual ArrayEntry do_array(const std::byte *bytes) const override;
	virtual std::pair<size_t, std::vector<MemberEntry>>
	do_struct(const std::byte *,
	    const std::function<std::string_view(uint)> &) const override;

	/* static function */
	static CtfTypeParser *create_symbol(const std::byte *data);
};

struct CtfType {
    protected:
	using CompareFunc = std::function<bool(const CtfType &lhs,
	    const CtfType &rhs, uint32_t l_child_id, uint32_t r_child_id)>;
	CtfTypeParser *parser;
	std::string_view name_str;
	ShrCtfData owned_ctf;
	uint32_t id;

	/* virtual function */
	virtual bool do_compare_impl(const CtfType &rhs,
	    const CompareFunc &comp)
	    const = 0; /* virtual function to implement each type comparasion
			  function */

	/* static function */
	static bool do_compare(const CtfType &lhs, const CtfType &rhs,
	    std::unordered_set<uint64_t> &visited,
	    std::unordered_map<uint64_t, bool>
		&cache); /* internal function for compare two types */
	static bool do_compare_child(const CtfType &lhs, const CtfType &rhs,
	    uint32_t l_child_id, uint32_t r_child_id,
	    std::unordered_set<uint64_t> &visited,
	    std::unordered_map<uint64_t, bool> &cache);

    public:
	/* constructor */
	CtfType(CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name, ShrCtfData owned_ctf)
	    : parser(parser)
	    , name_str(name)
	    , owned_ctf(owned_ctf)
	    , id(id) {};
	virtual ~CtfType();

	/* member function */
	inline const std::string_view &name() const { return name_str; }
	inline ShrCtfData get_owned() const { return owned_ctf; }
	bool compare(const CtfType &rhs,
	    std::unordered_map<uint64_t, bool> &cache)
	    const; /* compare two ctftype with type cache */
};

/*
 * a dummpy type for va_arg as ctf record it as id 0
 */
struct CtfTypeVaArg : CtfType {
    public:
	/* virtual function */
	virtual bool do_compare_impl(const CtfType &rhs,
	    const CompareFunc &comp) const override;

	/* constructor */
	CtfTypeVaArg(CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfType(parser, id, name, owned_ctf) {};
	virtual ~CtfTypeVaArg() = default;
};

struct CtfTypePrimitive : CtfType {
    protected:
	/* members */
	uint32_t data;

    public:
	/* virtual function */
	virtual bool do_compare_impl(const CtfType &rhs,
	    const CompareFunc &comp) const override;
	virtual uint32_t encoding() const = 0;
	virtual uint32_t offset() const = 0;
	virtual uint32_t width() const = 0;

	/* constructor */
	CtfTypePrimitive(uint32_t data, CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfType(parser, id, name, owned_ctf)
	    , data(data) {};
	virtual ~CtfTypePrimitive() = default;
};

struct CtfTypeInteger : CtfTypePrimitive {
	/* virtual function */
	virtual uint32_t encoding() const override;
	virtual uint32_t offset() const override;
	virtual uint32_t width() const override;

	/* cosntructor */
	CtfTypeInteger(uint32_t data, CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfTypePrimitive(data, parser, id, name, owned_ctf) {};
};

struct CtfTypeFloat : CtfTypePrimitive {
	/* virtual function */
	virtual uint32_t encoding() const override;
	virtual uint32_t offset() const override;
	virtual uint32_t width() const override;

	/* constructor */
	CtfTypeFloat(uint32_t data, CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfTypePrimitive(data, parser, id, name, owned_ctf) {};
};

struct CtfTypeArray : CtfType {
    private:
	/* members */
	ArrayEntry entry;

    public:
	/* virtual function */
	virtual bool do_compare_impl(const CtfType &rhs,
	    const CompareFunc &comp) const override;

	/* constructor */
	CtfTypeArray(const std::byte *data, CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfType(parser, id, name, owned_ctf)
	    , entry(parser->do_array(data)) {};

	/* member function */
	uint32_t members() const { return entry.nelems; };
};

struct CtfTypeFunc : CtfType {
    protected:
	/* members */
	uint32_t ret_id;
	std::vector<uint32_t> args_vec;

    public:
	/* virtual function */
	virtual bool do_compare_impl(const CtfType &rhs,
	    const CompareFunc &comp) const override;

	/* constructor */
	CtfTypeFunc(uint32_t ret_id, std::vector<uint32_t> &&args_vec,
	    CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfType(parser, id, name, owned_ctf)
	    , ret_id(ret_id)
	    , args_vec(args_vec) {};

	/* member function */
	const std::vector<uint32_t> &args() const { return args_vec; };
	uint32_t ret() const { return ret_id; };
};

struct CtfTypeEnum : CtfType {
    private:
	/* member */
	std::vector<std::pair<std::string_view, uint32_t>> members;

    public:
	/* virtual function */
	virtual bool do_compare_impl(const CtfType &rhs,
	    const CompareFunc &comp) const override;

	/* constructor */
	CtfTypeEnum(
	    std::vector<std::pair<std::string_view, uint32_t>> &&members,
	    CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfType(parser, id, name, owned_ctf)
	    , members(members) {};
};

struct CtfTypeForward : CtfType {
    public:
	/* virtual function */
	virtual bool do_compare_impl(const CtfType &rhs,
	    const CompareFunc &comp) const override;

	/* constructor */
	CtfTypeForward(CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfType(parser, id, name, owned_ctf) {};
};

struct CtfTypeQualifier : CtfType {
    protected:
	/* members */
	uint32_t ref_id;

    public:
	/* virtual function */
	virtual bool do_compare_impl(const CtfType &rhs,
	    const CompareFunc &comp) const override;

	/* constructor */
	CtfTypeQualifier(uint32_t ref_id, CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfType(parser, id, name, owned_ctf)
	    , ref_id(ref_id) {};

	virtual ~CtfTypeQualifier() = default;

	/* member function */
	uint32_t ref() const { return this->ref_id; }
};

struct CtfTypePtr : CtfTypeQualifier {
    public:
	/* constructor */
	CtfTypePtr(uint32_t ref_id, CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfTypeQualifier(ref_id, parser, id, name, owned_ctf) {};
};

struct CtfTypeTypeDef : CtfTypeQualifier {
    public:
	/* constructor */
	CtfTypeTypeDef(uint32_t ref_id, CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfTypeQualifier(ref_id, parser, id, name, owned_ctf) {};
};

struct CtfTypeVolatile : CtfTypeQualifier {
    public:
	/* constructor */
	CtfTypeVolatile(uint32_t ref_id, CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfTypeQualifier(ref_id, parser, id, name, owned_ctf) {};
};

struct CtfTypeConst : CtfTypeQualifier {
    public:
	/* constructor */
	CtfTypeConst(uint32_t ref_id, CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfTypeQualifier(ref_id, parser, id, name, owned_ctf) {};
};

struct CtfTypeRestrict : CtfTypeQualifier {
    public:
	/* constructor */
	CtfTypeRestrict(uint32_t ref_id, CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfTypeQualifier(ref_id, parser, id, name, owned_ctf) {};
};

struct CtfTypeUnknown : CtfType {
    public:
	/* virtual function */
	virtual bool do_compare_impl(const CtfType &rhs,
	    const CompareFunc &comp) const override;

	/* constructor */
	CtfTypeUnknown(CtfTypeParser *parser, uint32_t id,
	    ShrCtfData owned_ctf = nullptr)
	    : CtfType(parser, id, "", owned_ctf) {};
};

struct CtfTypeComplex : CtfType {
    protected:
	/* members */
	uint32_t size;
	std::vector<MemberEntry> args;

    public:
	/* constructor */
	CtfTypeComplex(uint32_t size, std::vector<MemberEntry> &&args,
	    CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfType(parser, id, name, owned_ctf)
	    , size(size)
	    , args(args) {};
	virtual ~CtfTypeComplex() = default;
};

struct CtfTypeStruct : CtfTypeComplex {
    public:
	/* virtual function */
	virtual bool do_compare_impl(const CtfType &rhs,
	    const CompareFunc &comp) const override;

	/* constructor */
	CtfTypeStruct(uint32_t size, std::vector<MemberEntry> &&args,
	    CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfTypeComplex(size,
		  std::forward<std::vector<MemberEntry> &&>(args), parser, id,
		  name, owned_ctf) {};
};

struct CtfTypeUnion : CtfTypeComplex {
    public:
	/* virtual function */
	virtual bool do_compare_impl(const CtfType &rhs,
	    const CompareFunc &comp) const override;

	/* constructor */
	CtfTypeUnion(uint32_t size, std::vector<MemberEntry> &&args,
	    CtfTypeParser *parser, uint32_t id,
	    const std::string_view &name = "", ShrCtfData owned_ctf = nullptr)
	    : CtfTypeComplex(size,
		  std::forward<std::vector<MemberEntry> &&>(args), parser, id,
		  name, owned_ctf) {};
};

using CtfTypeFactory = CtfTypeParser *(*)(const std::byte *);
using ShrCtfType = std::shared_ptr<CtfType>;
