#pragma once

#include <stdlib.h>

typedef struct Diff *Diff_t;

enum DIFF_DIR {
	LHS,
	RHS,
};

Diff_t inplace_diff(void *lhs, size_t lhs_nmemb, void *rhs, size_t rhs_nmemb,
    size_t size, int (*cmp)(const void *, const void *));

void **diff_extrat_greater(Diff_t diff, enum DIFF_DIR dir, size_t *size);
