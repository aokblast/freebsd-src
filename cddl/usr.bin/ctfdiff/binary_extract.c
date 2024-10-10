#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ctf.h>
#include <sys/mman.h>

#include "binary_extract.h"

Elf_Scn *get_section_from_ehdr(Elf *elf, GElf_Ehdr *ehdr, const char *sec_name) {
	char *name;
	GElf_Shdr shdr;
	Elf_Scn *sec = NULL;
	
	assert(sec_name != NULL);
#define NEXTSEC(elf, sec) (elf_nextscn(elf, sec))
	for (sec = NEXTSEC(elf, sec); sec != NULL; sec = NEXTSEC(elf, sec)) {
		if (gelf_getshdr(sec, &shdr) != NULL &&
			(name = elf_strptr(elf, ehdr->e_shstrndx, shdr.sh_name)) &&
			strcmp(sec_name, name) == 0) {
			return sec;
			
		}
	}
#undef NEXTSCN

	return NULL;
}



Ctf_Data *get_ctf_from_elf(Elf *elf) {
	const static char *ctf_secname = ".SUNW_ctf";
	const static char *sym_secname = ".symtab";
	Ctf_Data *ctf = NULL, *result = NULL;
	GElf_Ehdr *ehdr = NULL;
	Elf_Scn *ctf_scn = NULL, *sym_scn = NULL, *symstr_scn = NULL;
	Elf_Data *ctf_data = NULL;
	GElf_Shdr *ctf_shdr = NULL, *sym_shdr = NULL;

	assert((ctf = malloc(sizeof(Ctf_Data))) != NULL);

	if ((ehdr = gelf_getehdr(elf, NULL)) == NULL)
		goto clean;

	if ((ctf_scn = get_section_from_ehdr(elf, ehdr, ctf_secname)) == NULL)
		goto clean;

	if ((ctf_data = elf_getdata(ctf_scn, NULL)) == NULL)
		goto clean;

	ctf->ctf_addr = ctf_data->d_buf;
	ctf->ctf_size = ctf_data->d_size;
	result = ctf;

	if ((ctf_shdr = gelf_getshdr(ctf_scn, NULL)) == NULL)
		goto clean;

	// If we have linked section, we should grab the symbol table from elf hinted
	if (ctf_shdr->sh_link != 0) { 
		sym_scn = elf_getscn(elf, ctf_shdr->sh_link);
	} else {
		sym_scn = get_section_from_ehdr(elf, ehdr, sym_secname);
	}

	if (sym_scn != NULL
		&& (sym_shdr = gelf_getshdr(sym_scn, NULL)) == NULL)
		goto clean;

	symstr_scn = elf_getscn(elf, sym_shdr->sh_link);

	ctf->sym_nums = sym_shdr->sh_size / sym_shdr->sh_entsize;
	ctf->sym_addr = elf_getdata(sym_scn, NULL);
	ctf->symstr_addr = elf_getdata(symstr_scn, NULL);
	
  clean:
	if (sym_scn != NULL)
		free(sym_scn);

	if (ctf_shdr!= NULL)
		free(ctf_shdr);

	if (ctf_scn != NULL)
		free(ctf_scn);

	if (ehdr != NULL)
		free(ehdr);

	if (result != ctf)
		free(ctf);
	
	return result;
}

Ctf_Data *get_ctf_from_raw_file(int fd) {
	Ctf_Data *ctf, *result = NULL;
	struct stat stat;

	assert((ctf = malloc(sizeof(Ctf_Data))) != NULL);
	if (fstat(fd, &stat) == -1) {
		goto clean;
	}

	ctf->ctf_size = stat.st_size;
	ctf->ctf_addr = mmap(NULL, ctf->ctf_size, PROT_READ, MAP_PRIVATE, fd, 0);

	if (ctf->ctf_addr == MAP_FAILED)
		goto clean;

	result = ctf;
  clean:
	if (result != ctf)
		free(result);

	return ctf;
}
	
