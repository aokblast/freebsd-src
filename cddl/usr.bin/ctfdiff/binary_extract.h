#pragma once

#include <libelf.h>
#include <gelf.h>


typedef struct {
	caddr_t ctf_addr;
	size_t ctf_size;
	Elf_Data *sym_addr;
	size_t sym_nums;
	Elf_Data *symstr_addr;
	size_t ctf_idwidth;
} Ctf_Data;


Elf_Scn *get_section_from_ehdr(Elf *elf, GElf_Ehdr *ehdr, const char *sec_name);
Ctf_Data *get_ctf_from_elf(Elf *elf);
Ctf_Data *get_ctf_from_raw_file(int fd);
