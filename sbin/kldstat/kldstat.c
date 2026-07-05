/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1997 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <gelf.h>
#include <kldelf.h>
#include <libutil.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define	PTR_WIDTH ((int)(sizeof(void *) * 2 + 2))

static void printmod(int);
static void printfile(int, int, int);
static void usage(void) __dead2;

static int showdata = 0;

struct module_map_entry {
	char *module_name;
	char *ko_path;		/* shared by all modules from one file */
	char *prefix;
	SLIST_ENTRY(module_map_entry) entry;
};
static SLIST_HEAD(module_map_list, module_map_entry) module_map =
    SLIST_HEAD_INITIALIZER(module_map);

static void
clean_modules_mapping(void)
{
	struct module_map_entry *entry, *next;

	SLIST_FOREACH_SAFE(entry, &module_map, entry, next) {
		/*
		 * Entries from the same file are inserted consecutively
		 * and share one ko_path allocation; free it once, on the
		 * last entry of each run.
		 */
		if (next == NULL || next->ko_path != entry->ko_path)
			free(entry->ko_path);
		free(entry->prefix);
		free(entry->module_name);
		free(entry);
	}
	SLIST_INIT(&module_map);
}

static struct module_map_entry *
new_module_map_entry(char *ko_path)
{
	struct module_map_entry *entp;

	entp = calloc(1, sizeof(*entp));
	if (entp == NULL)
		err(1, "calloc");
	entp->ko_path = ko_path;
	return (entp);
}

static void
init_modules_mapping(void)
{
	struct module_map_entry *entp;
	struct kld_file_stat stat;
	struct module_stat mod_stat;
	const char *child_name;
	char *ko_path;
	int fileid, modid, nmod;

	if (!SLIST_EMPTY(&module_map))
		return;
	for (fileid = kldnext(0); fileid > 0; fileid = kldnext(fileid)) {
		stat.version = sizeof(struct kld_file_stat);
		if (kldstat(fileid, &stat) < 0)
			continue;
		/* All modules from this file share one copy of its path. */
		ko_path = strdup(stat.pathname);
		if (ko_path == NULL)
			err(1, "strdup");
		nmod = 0;
		if (strcmp(stat.name, "kernel") == 0) {
			entp = new_module_map_entry(ko_path);
			entp->module_name = strdup("kernel");
			if (entp->module_name == NULL)
				err(1, "strdup");
			SLIST_INSERT_HEAD(&module_map, entp, entry);
			nmod++;
		}
		for (modid = kldfirstmod(fileid); modid > 0;
		    modid = modfnext(modid)) {
			mod_stat.version = sizeof(struct module_stat);
			if (modstat(modid, &mod_stat) < 0)
				continue;
			entp = new_module_map_entry(ko_path);
			if ((child_name = strchr(mod_stat.name, '/')) != NULL) {
				entp->prefix = strndup(mod_stat.name,
				    child_name - mod_stat.name);
				entp->module_name = strdup(child_name + 1);
				if (entp->prefix == NULL)
					err(1, "strndup");
			} else
				entp->module_name = strdup(mod_stat.name);
			if (entp->module_name == NULL)
				err(1, "strdup");
			SLIST_INSERT_HEAD(&module_map, entp, entry);
			nmod++;
		}
		/* No entry references the path if the file had no modules. */
		if (nmod == 0)
			free(ko_path);
	}
	if (!SLIST_EMPTY(&module_map))
		atexit(clean_modules_mapping);
}

static void
print_module_dependency(const char *modname, const struct Gmod_depend *mdp)
{
	struct module_map_entry *entry;
	bool found = false;

	/*
	 * A module name is not unique: the same driver can attach to
	 * more than one bus (e.g. hidbus on usb and iic), so report
	 * every file that provides the dependency.
	 */
	SLIST_FOREACH(entry, &module_map, entry) {
		if (strcmp(entry->module_name, modname) != 0)
			continue;
		found = true;
		printf("\t\t  depends on %s.%d (%d,%d) => %s", modname,
		    mdp->md_ver_preferred, mdp->md_ver_minimum,
		    mdp->md_ver_maximum, entry->ko_path);
		if (entry->prefix != NULL)
			printf(" (%s)", entry->prefix);
		printf("\n");
	}
	if (!found)
		printf("\t\t  depends on %s.%d (%d,%d) => not found\n", modname,
		    mdp->md_ver_preferred, mdp->md_ver_minimum,
		    mdp->md_ver_maximum);
}

static void
printmod(int modid)
{
	struct module_stat stat;

	memset(&stat, 0, sizeof(stat));
	stat.version = sizeof(struct module_stat);
	if (modstat(modid, &stat) < 0) {
		warn("can't stat module id %d", modid);
		return;
	}
	if (showdata) {
		printf("\t\t%3d %s (%d, %u, 0x%lx)\n", stat.id,
		    stat.name, stat.data.intval, stat.data.uintval,
		    stat.data.ulongval);
	} else
		printf("\t\t%3d %s\n", stat.id, stat.name);
}

static void
print_file_dependency(const char *full_path)
{
	struct elf_file ef;
	struct Gmod_metadata md;
	struct Gmod_depend mdp;
	GElf_Addr *entries;
	char cval[MAXMODNAME + 1];
	long i, n;
	int error;

	init_modules_mapping();

	if (elf_open_file(&ef, full_path, 1) != 0)
		return;
	entries = NULL;
	error = elf_read_linker_set(&ef, MDT_SETNAME, &entries, &n);
	if (error != 0) {
		/* A file without module metadata has no dependencies. */
		if (error != ENOENT && error != ESRCH)
			warnc(error, "%s: can't read module metadata",
			    full_path);
		goto out;
	}
	for (i = 0; i < n; i++) {
		error = elf_read_mod_metadata(&ef, entries[i], &md);
		if (error != 0) {
			warnc(error, "%s: can't read module metadata",
			    full_path);
			goto out;
		}
		if (md.md_type != MDT_DEPEND)
			continue;
		error = elf_read_string(&ef, md.md_cval, cval, sizeof(cval));
		if (error != 0) {
			warnc(error, "%s: can't read module dependency name",
			    full_path);
			goto out;
		}
		error = elf_read_mod_depend(&ef, md.md_data, &mdp);
		if (error != 0) {
			warnc(error, "%s: can't read module dependency",
			    full_path);
			goto out;
		}
		print_module_dependency(cval, &mdp);
	}
out:
	free(entries);
	elf_close_file(&ef);
}

static void
printfile(int fileid, int verbose, int humanized)
{
	struct kld_file_stat stat;
	int modid;
	char buf[5];

	stat.version = sizeof(struct kld_file_stat);
	if (kldstat(fileid, &stat) < 0)
		err(1, "can't stat file id %d", fileid);
	if (humanized) {
		humanize_number(buf, sizeof(buf), stat.size,
		    "", HN_AUTOSCALE, HN_DECIMAL | HN_NOSPACE);

		printf("%2d %4d %*p %5s %s",
		    stat.id, stat.refs, PTR_WIDTH, stat.address,
		    buf, stat.name);
	} else {
		printf("%2d %4d %*p %8zx %s",
		    stat.id, stat.refs, PTR_WIDTH, stat.address,
		    stat.size, stat.name);
	}

	if (verbose) {
		printf(" (%s)\n", stat.pathname);
		printf("\tContains modules:\n");
		printf("\t\t Id Name\n");
		for (modid = kldfirstmod(fileid); modid > 0; modid = modfnext(modid))
			printmod(modid);
		printf("\tDependencies:\n");
		print_file_dependency(stat.pathname);
	} else
		printf("\n");
}

static void __dead2
usage(void)
{
	fprintf(stderr, "usage: %1$s [-dhqv] [-i id] [-n filename]\n"
	    "       %1$s [-dq] [-m modname]\n", getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct module_stat stat;
	int humanized = 0;
	int verbose = 0;
	int fileid = 0;
	int quiet = 0;
	int c, modid;
	char *filename = NULL;
	char *modname = NULL;
	char *p;

	while ((c = getopt(argc, argv, "dhi:m:n:qv")) != -1) {
		switch (c) {
		case 'd':
			showdata = 1;
			break;
		case 'h':
			humanized = 1;
			break;
		case 'i':
			fileid = (int)strtoul(optarg, &p, 10);
			if (*p != '\0')
				usage();
			break;
		case 'm':
			modname = optarg;
			break;
		case 'n':
			filename = optarg;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	if (verbose && elf_version(EV_CURRENT) == EV_NONE)
		errx(1, "unsupported libelf");

	if (modname != NULL) {
		if ((modid = modfind(modname)) < 0) {
			if (!quiet)
				warn("can't find module %s", modname);
			return (1);
		} else if (quiet)
			return (0);

		stat.version = sizeof(struct module_stat);
		if (modstat(modid, &stat) < 0)
			warn("can't stat module id %d", modid);
		else {
			if (showdata) {
				printf("Id  Refs Name data..(int, uint, ulong)\n");
				printf("%3d %4d %s (%d, %u, 0x%lx)\n",
				    stat.id, stat.refs, stat.name,
				    stat.data.intval, stat.data.uintval,
				    stat.data.ulongval);
			} else {
				printf("Id  Refs Name\n");
				printf("%3d %4d %s\n", stat.id, stat.refs,
				    stat.name);
			}
		}

		return (0);
	}

	if (filename != NULL) {
		if ((fileid = kldfind(filename)) < 0) {
			if (!quiet)
				warn("can't find file %s", filename);
			return (1);
		} else if (quiet)
			return (0);
	}

	if (humanized) {
		printf("Id Refs Address%*c %5s Name\n", PTR_WIDTH - 7,
		    ' ', "Size");
	} else {
		printf("Id Refs Address%*c %8s Name\n", PTR_WIDTH - 7,
		    ' ', "Size");
	}
	if (fileid != 0)
		printfile(fileid, verbose, humanized);
	else
		for (fileid = kldnext(0); fileid > 0; fileid = kldnext(fileid))
			printfile(fileid, verbose, humanized);

	return (0);
}
