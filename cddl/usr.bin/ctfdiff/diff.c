#include <assert.h>
#include <stdlib.h>

#include "diff.h"

struct Diff {
	int l_size;
	void **l_diff;
	int r_size;
	void **r_diff;
};

Diff_t inplace_diff(void *lhs, size_t lhs_nmemb,
					void *rhs, size_t rhs_nmemb, size_t size,
					int (*cmp)(const void *, const void*)) {
	char *l = lhs;
	char *r = rhs;
	size_t l_idx = 0, r_idx = 0;
	Diff_t diff;

	assert((diff = calloc(sizeof(struct Diff), 1)) != NULL);
	
	qsort(l, lhs_nmemb, size, cmp);
	qsort(r, rhs_nmemb, size, cmp);

	while(l_idx < lhs_nmemb && r_idx < rhs_nmemb) {
		int cmp_res = cmp(l + l_idx * size, r + r_idx * size);

		if (cmp_res > 0) {
			
		} else if (cmp_res < 0) {
		}
	}

	return diff;
}


void **diff_extrat_greater(Diff_t diff , enum DIFF_DIR dir, size_t *size) {
	switch(dir) {
	case LHS:
		*size = diff->l_size;
		return diff->l_diff;
	case RHS:
		*size = diff->r_size;
		return diff->r_diff;
	}

	*size = 0;
	return NULL;
}
