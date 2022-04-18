/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2007-2016 Arnaldo Carvalho de Melo <acme@kernel.org>
  Copyright (C) 2022 Alibek Omarov <a1ba.omarov@gmail.com>
*/

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "dwarves.h"
#include "dutil.h"

static bool g_strip_upper_directory = false;

#define IGNORE_UPPER_DIRECTORY 1
#define NO_WRITE_FILES 0

char *strncpy2(char *dest, const char *src, size_t n)
{
	char *ret = strncpy(dest, src, n);
	dest[n] = 0;
	return ret;
}

static bool endswith(const char *s1, const char *s2)
{
	int len1 = strlen(s1);
	int len2 = strlen(s2);

	if( len1 < len2 )
		return false;

	return !strncmp(s1 + len1 - len2, s2, len2);
}

static bool filename_looks_like_header(const char *s1)
{
	return endswith(s1, ".h") || endswith(s1, ".H");
}

static int startswith( const char *s1, const char *s2 )
{
	int len2 = strlen(s2);

	if( !strncmp(s1, s2, len2))
		return len2;

	return 0;
}

static void mkdir_p(const char *path)
{
#if NO_WRITE_FILES
	return;
#else
	char orig_dir[2048];
	getcwd(orig_dir, sizeof( orig_dir ));

	for(const char *path2 = path; (path2 = strchr(path, '/')); path = path2 + 1)
	{
		char dir[128];

		strncpy2(dir, path, path2 - path);

		mkdir(dir, 0777);

		chdir(dir);
	}

	chdir(orig_dir);
#endif
}

// ========================================================================

typedef struct
{
	struct list_head node;
	int linenum;
	char *include;
	struct tag *tag;
	struct cu *cu;
} srcfile_line_t;

typedef struct
{
	struct list_head node;
	const char *filename;
	struct list_head lines;
} srcfile_t;

LIST_HEAD(g_SourceFiles);

typedef struct include_t 
{
	struct list_head node;
	char *filename;
	struct include_t *parent;
} include_t;

LIST_HEAD(g_Includes);

static srcfile_t *find_or_create_srcfile(const char *filename);
static bool find_or_insert_line(srcfile_t *sourceFile, int linenum, struct tag *tag, struct cu *cu, const char *include);

static void include_detector_init( void )
{
	include_t *ptr, *next;

	list_for_each_entry_safe(ptr, next, &g_Includes, node)
	{
		list_del(&ptr->node);
		free(ptr->filename);
		free(ptr);
	}

	INIT_LIST_HEAD(&g_Includes);
}

static void include_detector_push(const char *filename)
{
	include_t *include;

	include = malloc( sizeof( include_t ));
	include->filename = strdup( filename );
	include->parent = NULL;
	list_add_tail(&include->node, &g_Includes);
}

static void include_detector_detect1(struct cu *cu)
{
	include_t *inc1;

	// for each include we find next duplicate
	// it PROBABLY means that everything in between
	// belongs to that include
// 	list_for_each_entry(inc1, &g_Includes, node)
// 	{
// 		include_t *inc2;
// 		
// 		list_for_each_entry(inc2, inc1->node.next, node)
// 		{
// 			include_t *inc3;
// 
// 			if( strcmp( inc1->filename, inc2->filename ))
// 				continue;
// 
// 			list_for_each_entry_reverse(inc3, inc2->node.prev, node)
// 			{
// 				if( inc1 == inc3 )
// 					break;
// 
// 				inc3->parent = inc1;
// 			}
// 		}
// 	}
	
	list_for_each_entry(inc1, &g_Includes, node)
	{
		if( filename_looks_like_header( inc1->filename ))
		{
			srcfile_t *srcfile = find_or_create_srcfile(cu->name);
			
			if( srcfile )
				find_or_insert_line(srcfile, -1, NULL, NULL, inc1->filename);
		}
	}
}

static srcfile_t *find_or_create_srcfile(const char *filename)
{
	srcfile_t *srcfile;

	filename += startswith( filename, "/" );


	if( !g_strip_upper_directory )
	{
		if( startswith( filename, "../" ))
			return NULL;
	}

	if( startswith( filename, "usr/" ))
		return NULL;

	if( startswith( filename, "fs/root/build/host/glibc-2.29/" )) 
		return NULL;

	if( g_strip_upper_directory )
		filename += startswith( filename, "../" );

	filename += startswith( filename, "/fs/root/build/x86_64/lccrt/" );
	filename += startswith( filename, "fs/root/build/x86_64/lccrt/" );
	filename += startswith( filename, "./" );
	filename += startswith( filename, ".obj/" );
	include_detector_push(filename);

	list_for_each_entry(srcfile, &g_SourceFiles, node)
	{
		if( !strcmp( srcfile->filename, filename ))
		{
			return srcfile;
		}
	}

	srcfile = malloc( sizeof( srcfile_t ));
	srcfile->filename = strdup(filename);
	INIT_LIST_HEAD(&srcfile->lines);

	list_add_tail(&srcfile->node, &g_SourceFiles);

	return srcfile;
}

static bool find_or_insert_line(srcfile_t *sourceFile, int linenum, struct tag *tag, struct cu *cu, const char *include)
{
	srcfile_line_t *line, *new;

	list_for_each_entry_reverse(line, &sourceFile->lines, node)
	{
		if( line->linenum == linenum ) // && tag__orig_id(line->tag, line->cu) == tag__orig_id(tag, cu))
		{
			// special case for include insert
			if( line->include )
				break;

			line->tag = tag;
			line->cu = cu;
			return false;
		}

		if( line->linenum <= linenum )
			break;
	}

	new = malloc( sizeof( srcfile_line_t ));
	new->linenum = linenum;
	new->tag = tag;
	new->cu = cu;
	new->include = include ? strdup(include) : 0;
	list_add(&new->node, &line->node);

	return true;
}

static void add_srcfile_tag(struct tag *tag, struct cu *cu)
{
	const char *file = tag__decl_file(tag, cu);
	srcfile_t *srcfile;

	if( !file )
		return;

	srcfile = find_or_create_srcfile(file);

	if( srcfile )
		find_or_insert_line(srcfile, tag__decl_line(tag, cu), tag, cu, NULL);
}

// ========================================================================

static struct conf_fprintf conf = {
	.emit_stats	= 0,
	.classes_as_structs = 1,
};

static void print_type(struct tag *tag, struct cu *cu, FILE *fp)
{
	fprintf(fp, "/* line: %i */\n", tag__decl_line(tag, cu));

	if (tag__is_struct(tag))
		class__find_holes(tag__class(tag));

	tag__fprintf(tag, cu, &conf, fp);

	fprintf(fp, " /* size: %zd */\n\n", tag__size(tag, cu));
}

static void print_function(struct tag *tag, struct cu *cu, FILE *fp)
{
	conf.no_semicolon = true;
	{
		struct function *f = tag__function(tag);
		int c = tag__fprintf(tag, cu, &conf, fp);
		if( c >= 70 ) c = 69; // nice

		fprintf(fp, "%-*.*s// %5u\n", 70 - c, 70 - c, " ",
			 tag__decl_line(tag, cu));
		lexblock__fprintf(&f->lexblock, cu, f, 0, &conf, fp);
		fputs("\n\n", fp);
	}
	conf.no_semicolon = false;
}

static void print_variable(struct tag *tag, struct cu *cu, FILE *fp)
{
	tag__fprintf(tag, cu, NULL, fp);
	fprintf(fp, " /* line: %i, size: %zd, scope: %s */\n\n", tag__decl_line(tag, cu), tag__size(tag, cu), variable__scope_str(tag__variable(tag)));
}

static void source_files_print( void )
{
	srcfile_t *srcfile;

	list_for_each_entry(srcfile, &g_SourceFiles, node)
	{
		printf( "SOURCE FILE: %s\n", srcfile->filename );

		mkdir_p( srcfile->filename );

		FILE *fp = fopen( srcfile->filename, "w+" );

		srcfile_line_t *line;
		bool header = filename_looks_like_header( srcfile->filename );

		fprintf( fp, "// Generated by psrcgen tool\n" );

		if( header )
		{
			fprintf( fp, "#pragma once\n" );
		}
		else
		{
			fprintf( fp, "#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n" );
		}

		list_for_each_entry(line, &srcfile->lines, node)
		{
			if( line->include )
			{
				fprintf(fp, "#include \"%s\"\n", line->include );
			}
			else if( tag__is_type(line->tag))
			{
				print_type(line->tag, line->cu, fp);
			}
			else if( tag__is_variable(line->tag))
			{
				print_variable(line->tag, line->cu, fp );
			}
			else if( tag__is_function(line->tag))
			{
				print_function(line->tag, line->cu, fp );
			}
		}

		fclose(fp);
	}
}

// ========================================================================

static void scan_type(struct tag *tag, struct cu *cu)
{
	const char *name;

	switch(tag->tag)
	{
	case DW_TAG_base_type:
	case DW_TAG_const_type:
	case DW_TAG_array_type:
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type:
	case DW_TAG_subroutine_type:
	case DW_TAG_unspecified_type:
	case DW_TAG_rvalue_reference_type:
	case DW_TAG_restrict_type:
	case DW_TAG_volatile_type:
		return;
	}

	name = type__name(tag__type(tag));
	// probably included
	if( name == NULL )
		return;

	if( name[0] == '\0' )
		return;

	// probably a forward declaration, skip for now
	if( tag__size(tag, cu) == 0 )
		return;

	add_srcfile_tag(tag, cu);
}

static void scan_variable(struct tag *tag, struct cu *cu)
{
	struct variable *variable = tag__variable(tag);

	if( variable->scope == VSCOPE_LOCAL )
		return;

	add_srcfile_tag(tag, cu);
}

static int cu__emit_tags(struct cu *cu)
{
	uint32_t i;
	struct tag *tag;
	struct function *function;

	include_detector_init();

	cu__for_each_type(cu, i, tag) {
		scan_type(tag, cu);
	}

	cu__for_each_variable(cu, i, tag) {
		scan_variable(tag, cu);
	}

	cu__for_each_function(cu, i, function) {
		add_srcfile_tag(function__tag(function), cu);
	}

	include_detector_detect1(cu);

	return 0;
}

static enum load_steal_kind psrcgen_stealer(struct cu *cu,
					    struct conf_load *conf_load __maybe_unused,
					    void *thr_data __maybe_unused)
{
	cu__emit_tags(cu);

	return LSK__KEEPIT;
}

static struct conf_load psrcgen_conf_load = {
	.steal = psrcgen_stealer,
	.conf_fprintf = &conf,
	.extra_dbg_info = 1,
	.get_addr_info = 1,
};

/* Name and version of program.  */
ARGP_PROGRAM_VERSION_HOOK_DEF = dwarves_print_version;

static const struct argp_option psrcgen__options[] = {
	{
		.name = "format_path",
		.key  = 'F',
		.arg  = "FORMAT_LIST",
		.doc  = "List of debugging formats to try",
	},
	{
		.name = "classes_as_structs",
		.key  = 'S',
		.doc  = "force classes to be presented as structs",
	},
	{
		.name = "strip_upper_directory",
		.key  = 'u',
		.doc  = "strip upper directory from file paths",
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

static error_t psrcgen__options_parser(int key, char *arg __maybe_unused,
				      struct argp_state *state)
{
	switch (key) {
	case ARGP_KEY_INIT:
		if (state->child_inputs != NULL)
			state->child_inputs[0] = state->input;
		break;
	case 'F': psrcgen_conf_load.format_path = arg;	break;
	case 'V': conf.show_decl_info = 1;		break;
	case 'S': conf.classes_as_structs = 1;		break;
	case 'u': g_strip_upper_directory = true;	break;
	default:  return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const char psrcgen__args_doc[] = "FILE";

static struct argp psrcgen__argp = {
	.options  = psrcgen__options,
	.parser	  = psrcgen__options_parser,
	.args_doc = psrcgen__args_doc,
};

int main(int argc, char *argv[])
{
	int remaining, rc = EXIT_FAILURE, err;
	struct cus *cus = cus__new();

	if (dwarves__init() || cus == NULL) {
		fputs("psrcgen: insufficient memory\n", stderr);
		goto out;
	}

	dwarves__resolve_cacheline_size(&psrcgen_conf_load, 0);

	if (argp_parse(&psrcgen__argp, argc, argv, 0, &remaining, NULL) ||
	    remaining == argc) {
                argp_help(&psrcgen__argp, stderr, ARGP_HELP_SEE, argv[0]);
                goto out;
	}

	err = cus__load_file(cus, &psrcgen_conf_load, argv[remaining]);
	if (err == 0) {
		rc = EXIT_SUCCESS;
		source_files_print();
		goto out;
	}

	cus__fprintf_load_files_err(cus, "psrcgen", argv + remaining, err, stderr);
out:
	cus__delete(cus);
	dwarves__exit();
	return rc;
}

