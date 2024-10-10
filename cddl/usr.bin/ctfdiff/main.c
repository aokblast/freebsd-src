#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ctf.h>
#include <sys/mman.h>
#include <zlib.h>

#include "binary_extract.h"
#include "ctf_headers.h"

int
main(int argc, char *argv[]) {
	int fd = -1;
	Elf *elf_file = NULL;
	Ctf_Data *ctf_data = NULL;
	void *ctf_content = NULL;
	ctf_preamble_t *ctf_preamble;
	ctf_header_t *header;

	(void) elf_version(EV_CURRENT);

	// TODO: parse args
	assert(argc == 2);

	if ((fd = open(argv[1], O_RDONLY)) == -1)
		goto clean;

	if ((elf_file = elf_begin(fd, ELF_C_READ, NULL)) == NULL ||
		(ctf_data = get_ctf_from_elf(elf_file)) == NULL) {
			ctf_data = get_ctf_from_raw_file(fd);
	}

	if (ctf_data == NULL)
		goto clean;

	if (ctf_data->ctf_size < sizeof(ctf_preamble_t))
		goto clean;

	ctf_content = ctf_data->ctf_addr;
	ctf_preamble = ctf_content;

	if (ctf_preamble->ctp_magic != CTF_MAGIC) {
		printf("%s does not contain a valid preamable\n", argv[1]);
		goto clean;
	}

	if (ctf_preamble->ctp_version < CTF_VERSION_2) {
		printf("Unsupported CTF version %d\n", ctf_preamble->ctp_version);		
		goto clean;
	}

	ctf_data->ctf_idwidth = ctf_preamble->ctp_version == CTF_VERSION_2 ? 2 : 4;

	header = ctf_content;
	if (ctf_data->ctf_size < sizeof(ctf_header_t)) {
		printf("Invalid ctf header in %s\n", argv[1]);
		goto clean;
	}

	ctf_data->ctf_addr += sizeof(ctf_header_t);
	
	if (header->cth_flags | CTF_F_COMPRESS) {

	}
clean:
	if (ctf_data != NULL)
		free(ctf_data);

	if (elf_file != NULL)
		elf_end(elf_file);
	
	if (fd != -1)
		close(fd);
}
