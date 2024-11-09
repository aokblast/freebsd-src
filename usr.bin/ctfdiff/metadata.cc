#include <sys/mman.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

#include "ctfdata.hpp"
#include "metadata.hpp"
#include <cstddef>
#include <iostream>

static Elf_Scn *
find_section_by_name(Elf *elf, GElf_Ehdr *ehdr, const std::string &sec_name)
{
	GElf_Shdr shdr;
	Elf_Scn *scn = NULL;
	const char *name;

#define NEXTSCN(elf, scn) elf_nextscn(elf, scn)
	for (scn = NEXTSCN(elf, scn); scn != NULL; scn = NEXTSCN(elf, scn)) {
		if (gelf_getshdr(scn, &shdr) != NULL &&
		    (name = elf_strptr(elf, ehdr->e_shstrndx, shdr.sh_name)) &&
		    sec_name == name) {
			return (scn);
		}
	}
#undef NEXTSCN

	return (nullptr);
}

bool
CtfMetaData::from_elf_file()
{
	static constexpr char ctfscn_name[] = ".SUNW_ctf";
	static constexpr char symscn_name[] = ".symtab";
	GElf_Ehdr ehdr;
	GElf_Shdr ctfshdr;

	if ((this->elf = elf_begin(this->data_fd, ELF_C_READ, NULL)) == NULL ||
	    gelf_getehdr(elf, &ehdr) == NULL) {
		return (false);
	}

	Elf_Scn *ctfscn = find_section_by_name(this->elf, &ehdr, ctfscn_name);
	Elf_Data *ctfscn_data;

	if (ctfscn == NULL ||
	    (ctfscn_data = elf_getdata(ctfscn, NULL)) == NULL) {
		std::cout << "Cannot find " << ctfscn_name
			  << " in file: " << this->filename << '\n';
		return (false);
	}

	this->ctfdata = Buffer(static_cast<std::byte *>(ctfscn_data->d_buf),
	    ctfscn_data->d_size);

	Elf_Scn *symscn;

	if (gelf_getshdr(ctfscn, &ctfshdr) != NULL && ctfshdr.sh_link != 0)
		symscn = elf_getscn(elf, ctfshdr.sh_link);
	else
		symscn = find_section_by_name(elf, &ehdr, symscn_name);

	if (symscn != NULL) {
		GElf_Shdr symshdr;
		Elf_Data *symsecdata;
		Elf_Data *symstrdata;
		Elf_Scn *symstrscn;

		if (gelf_getshdr(symscn, &symshdr) != NULL) {
			symstrscn = elf_getscn(elf, symshdr.sh_link);
			symsecdata = elf_getdata(symscn, NULL);
			symstrdata = elf_getdata(symstrscn, NULL);

			this->symdata = Buffer(static_cast<std::byte *>(
						   symsecdata->d_buf),
			    symsecdata->d_size,
			    symshdr.sh_size / symshdr.sh_entsize);
			this->strdata = Buffer(static_cast<std::byte *>(
						   symstrdata->d_buf),
			    symstrdata->d_size);
			this->symdata.elfdata = symsecdata;
			this->strdata.elfdata = symstrdata;
		}
	}

	return (true);
}

bool
CtfMetaData::from_raw_file()
{
	struct stat st;
	std::byte *bytes;

	if (fstat(this->data_fd, &st) == -1) {
		std::cout << "Failed to do fstat\n";
		close(this->data_fd);
		return (false);
	}

	bytes = static_cast<std::byte *>(
	    mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, this->data_fd, 0));

	if (bytes == MAP_FAILED) {
		std::cout << "Failed to do mmap\n";
		close(this->data_fd);
		return (false);
	}

	this->ctfdata = Buffer(bytes, st.st_size);
	return (true);
}

CtfMetaData::CtfMetaData(const std::string &filename)
    : filename(filename)
{
	this->data_fd = open(filename.c_str(), O_RDONLY);
	this->elf = nullptr;

	if (this->data_fd == -1) {
		return;
	}

	if (!this->from_elf_file()) {
		if (!this->from_raw_file()) {
			close(this->data_fd);
			this->data_fd = -1;
		}
	}
}

bool
CtfMetaData::is_available()
{
	return (this->data_fd != -1);
}

CtfMetaData::~CtfMetaData()
{
	if (this->elf)
		elf_end(this->elf);
	if (this->data_fd != -1)
		close(this->data_fd);
}
