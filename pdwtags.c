/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2007-2016 Arnaldo Carvalho de Melo <acme@kernel.org>
*/

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include "dwarves.h"
#include "dutil.h"

static struct conf_fprintf conf = {
	.emit_stats	= 0,
};

struct header_line_t
{
	struct list_item node;
	struct tag *tag;
};

struct header_info_t
{
	struct list_item node;
	const char *filename;
};

FILE *fd = NULL;

char *strncpy2(char *dest, const char *src, size_t n)
{
	char *ret = strncpy(dest, src, n);
	dest[n] = 0;
	return ret;
}

static void mkdir_p(const char *path)
{
	for(const char *path2 = path; (path2 = strchr(path, '/')); path = path2 + 1)
	{
		char dir[128];

		strncpy2(dir, path, path2 - path);
		printf("Creating dir: %s\n", dir);
	}
}

static void emit_tag(struct tag *tag, uint32_t tag_id, struct cu *cu)
{
	printf("/* %d */\n", tag_id);

	if (tag__is_struct(tag))
		class__find_holes(tag__class(tag));

	if (tag->tag == DW_TAG_base_type) {
		char bf[64];
		const char *name = base_type__name(tag__base_type(tag), bf, sizeof(bf));

		if (name == NULL)
			printf("anonymous base_type\n");
		else
			puts(name);
	} else if (tag__is_pointer(tag))
		printf(" /* pointer to %lld */\n", (unsigned long long)tag->type);
	else
		tag__fprintf(tag, cu, &conf, stdout);

	printf(" /* size: %zd */\n\n", tag__size(tag, cu));
}

int exits = 1;

static int cu__emit_tags(struct cu *cu)
{
	uint32_t i;
	struct tag *tag;
	
	if(!strncmp(cu->name, "../", 3))
	{
		return 0;
	}
	
	mkdir_p(cu->name);

	printf("FILENAME: %s\n", cu->name);

	puts("/* Types: */");
	cu__for_each_type(cu, i, tag)
	{
		switch(tag->tag)
		{
		case DW_TAG_base_type:
		case DW_TAG_const_type:
			continue;
		}
		
		printf("\ndeclared at %s:%i", tag__decl_file(tag, cu), tag__decl_line(tag, cu));
		
		emit_tag(tag, i, cu);
	}

	puts("\n/* Functions: */");
	conf.no_semicolon = true;
	struct function *function;
	cu__for_each_function(cu, i, function) {
		
		printf("\ndeclared at %s:%i", tag__decl_file(function__tag(function), cu), tag__decl_line(function__tag(function), cu));
		//tag__fprintf(function__tag(function), cu, &conf, stdout);
		//putchar('\n');
		//lexblock__fprintf(&function->lexblock, cu, function, 0,
		//		  &conf, stdout);
	}
	conf.no_semicolon = false;

	puts("\n/* Variables: */");
	cu__for_each_variable(cu, i, tag) {
		printf("\ndeclared at %s:%i", tag__decl_file(tag, cu), tag__decl_line(tag, cu));
		//tag__fprintf(tag, cu, NULL, stdout);
		//printf(" /* size: %zd */\n", tag__size(tag, cu));
	}

	if( !exits-- ) exit(0);

	return 0;
}

static enum load_steal_kind pdwtags_stealer(struct cu *cu,
					    struct conf_load *conf_load __maybe_unused,
					    void *thr_data __maybe_unused)
{
	cu__emit_tags(cu);
	return LSK__DELETE;
}

static struct conf_load pdwtags_conf_load = {
	.steal = pdwtags_stealer,
	.conf_fprintf = &conf,
	.extra_dbg_info = 1,
};

/* Name and version of program.  */
ARGP_PROGRAM_VERSION_HOOK_DEF = dwarves_print_version;

static const struct argp_option pdwtags__options[] = {
	{
		.name = "format_path",
		.key  = 'F',
		.arg  = "FORMAT_LIST",
		.doc  = "List of debugging formats to try"
	},
	{
		.key  = 'V',
		.name = "verbose",
		.doc  = "show details",
	},
	{
		.name = NULL,
	}
};

static error_t pdwtags__options_parser(int key, char *arg __maybe_unused,
				      struct argp_state *state)
{
	switch (key) {
	case ARGP_KEY_INIT:
		if (state->child_inputs != NULL)
			state->child_inputs[0] = state->input;
		break;
	case 'F': pdwtags_conf_load.format_path = arg;	break;
	case 'V': conf.show_decl_info = 1;		break;
	default:  return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char pdwtags__args_doc[] = "FILE";

static struct argp pdwtags__argp = {
	.options  = pdwtags__options,
	.parser	  = pdwtags__options_parser,
	.args_doc = pdwtags__args_doc,
};

int main(int argc, char *argv[])
{
	int remaining, rc = EXIT_FAILURE, err;
	struct cus *cus = cus__new();

	if (dwarves__init() || cus == NULL) {
		fputs("pwdtags: insufficient memory\n", stderr);
		goto out;
	}

	dwarves__resolve_cacheline_size(&pdwtags_conf_load, 0);

	if (argp_parse(&pdwtags__argp, argc, argv, 0, &remaining, NULL) ||
	    remaining == argc) {
                argp_help(&pdwtags__argp, stderr, ARGP_HELP_SEE, argv[0]);
                goto out;
	}

	err = cus__load_files(cus, &pdwtags_conf_load, argv + remaining);
	if (err == 0) {
		rc = EXIT_SUCCESS;
		goto out;
	}

	cus__fprintf_load_files_err(cus, "pdwtags", argv + remaining, err, stderr);
out:
	cus__delete(cus);
	dwarves__exit();
	return rc;
}
