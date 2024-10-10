#include <assert.h>
#include <sys/ctf.h>
#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>

#include "binary_extract.h"
#include "ctf.h"

void zlib_decompress_ctf(Ctf_Data *data, ctf_header_t *header) {
	z_stream zs;
	void *buffer, *result = NULL;
	size_t buffer_size;
	int ret;

	buffer_size = header->cth_stroff + header->cth_strlen;

	assert((buffer = calloc(buffer_size, 1)) == NULL);

	zs.next_in = data->ctf_addr;
	zs.avail_in = data->ctf_size;
	zs.next_out = buffer;
	zs.avail_out = buffer_size;

	if ((ret = inflateInit(&zs)) != Z_OK) {
		printf("failed to initialize zlib: %s", zError(ret));
		goto clean;
	}

	if ((ret = inflate(&zs, Z_FINISH)) != Z_STREAM_END) {
		printf("unable to inflate file: %s", zError(ret));
		goto clean;
	}

	if ((ret = inflateEnd(&zs)) != Z_OK) {
		printf("failed to finish decompression: %s", zError(ret));
		goto clean;
	}

	if (zs.total_out != buffer_size) {
		printf("CTF data is corrupted\n");
		goto clean;
	}

	data->ctf_addr = buffer;
	data->ctf_size = buffer_size;
	result = buffer;
  clean:
	if (buffer != result)
		free(buffer);
}
