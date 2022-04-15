/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2007-2016 Arnaldo Carvalho de Melo <acme@kernel.org>
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

static struct conf_fprintf conf = {
	.emit_stats	= 0,
};

typedef struct
{
	struct list_head node;
	int linenum;
	struct tag *tag;
	struct cu *cu;
} header_line_t;

typedef struct
{
	struct list_head node;
	const char *filename;
	struct list_head lines;
} header_info_t;

LIST_HEAD(headers);

char *strncpy2(char *dest, const char *src, size_t n)
{
	char *ret = strncpy(dest, src, n);
	dest[n] = 0;
	return ret;
}

static bool strcaseendswith(const char *s1, const char *s2)
{
	int len1 = strlen(s1);
	int len2 = strlen(s2);
	
	if( len1 < len2 )
		return false;
	
	return !strcasecmp(s1 + len1 - len2, s2);
}

static int strcasestartswith( const char *s1, const char *s2 )
{
	int len2 = strlen(s2);
	
	if( !strncasecmp(s1, s2, len2))
		return len2;
	
	return 0;
}

static bool filename_looks_like_header(const char *filename)
{
	return strcaseendswith(filename, ".h");
}

static header_info_t *find_or_create_header(const char *filename)
{
	header_info_t *header;
	
	if( strcasestartswith( filename, "../" ))
		return NULL;
	
	if( strcasestartswith( filename, "/usr/" ))
		return NULL;
	
	if( strcasestartswith( filename, "/fs/root/build/host/glibc-2.29/" ))
		return NULL;
	
	filename += strcasestartswith( filename, "/fs/root/build/x86_64/lccrt/" );
	filename += strcasestartswith( filename, "fs/root/build/x86_64/lccrt/" );
	filename += strcasestartswith( filename, "./" );
	filename += strcasestartswith( filename, ".obj/" );

	
	list_for_each_entry(header, &headers, node)
	{
		if( !strcmp( header->filename, filename ))
		{
			return header;
		}
	}
	
	header = malloc( sizeof( header_info_t ));
	header->filename = strdup(filename);
	INIT_LIST_HEAD(&header->lines);
	
	list_add_tail(&header->node, &headers);
	
	return header;
}

static bool find_or_insert_line(header_info_t *header, int linenum, struct tag *tag, struct cu *cu)
{
	header_line_t *line, *new;
	
	list_for_each_entry_reverse(line, &header->lines, node)
	{
		if( line->linenum == linenum ) // && tag__orig_id(line->tag, line->cu) == tag__orig_id(tag, cu))
		{
			line->tag = tag;
			line->cu = cu;
			return false;
		}
		
		if( line->linenum <= linenum )
			break;
	}
	
	new = malloc( sizeof( header_line_t ));
	new->linenum = linenum;
	new->tag = tag;
	new->cu = cu;
	list_add(&new->node, &line->node);
	
	return true;
}

static void add_header_tag(const char *file, struct tag *tag, struct cu *cu, FILE *fp)
{
	//static const char *prev = NULL;
	
	header_info_t *header;
	header = find_or_create_header(file);
	
	if( header )
	{
		find_or_insert_line(header, tag__decl_line(tag, cu), tag, cu);
		
#if 0
		if( prev != header->filename )
		{
			fprintf( fp, "#include \"%s\"\n", header->filename);
		}
		prev = header->filename;
#endif
	}
}

static void emit_tag(struct tag *tag, struct cu *cu, FILE *fp)
{
	if (tag__is_struct(tag))
		class__find_holes(tag__class(tag));

	if (tag__is_pointer(tag))
		fprintf(fp, " /* pointer to %lld %s */\n", (unsigned long long)tag->type, dwarf_tag_name(tag->tag));
	else
		tag__fprintf(tag, cu, &conf, fp);
	
	fprintf(fp, " /* size: %zd */\n\n", tag__size(tag, cu));
}

static void print_types(struct cu *cu, struct tag *tag, bool header, FILE *fp)
{
	const char *file;
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
	
	file = header ? 0 : tag__decl_file(tag, cu);
	if( file && filename_looks_like_header( file ))
	{
		add_header_tag(file, tag, cu, fp);
	}
	else
	{
		// probably a forward declaration, skip for now
		if( tag__size(tag, cu) == 0 )
			return;
		
		emit_tag(tag, cu, fp);
	}
}

static void print_variables(struct cu *cu, struct tag *tag, bool header, FILE *fp)
{
	const char *file = header ? 0 : tag__decl_file(tag, cu);
	if( file && filename_looks_like_header( file ))
	{
		add_header_tag(file, tag, cu, fp);
	}
	else
	{
		struct variable *variable = tag__variable(tag);
		
		if( variable->scope == VSCOPE_LOCAL )
			return;
		
		tag__fprintf(tag, cu, NULL, fp);
		fprintf(fp, " /* size: %zd scope: %s */\n", tag__size(tag, cu), variable__scope_str(variable));
	}
}

static void print_functions(struct cu *cu, struct function *function, bool header, FILE *fp)
{
	const char *file;
	struct tag *tag = function__tag(function);

	file = header ? 0 : tag__decl_file(tag, cu);
	if( file && filename_looks_like_header( file ))
	{
		add_header_tag(file, tag, cu, fp);
	}
	else
	{
		tag__fprintf(tag, cu, &conf, fp);
		fputs("\n", fp);
		lexblock__fprintf(&function->lexblock, cu, function, 0,
			  &conf, fp);
		fputs("\n\n", fp);
	}
}

#define NO_WRITE_FILES 0

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

static void headers_print( void )
{
	header_info_t *header;
	
	list_for_each_entry(header, &headers, node)
	{
		printf( "HEADER: %s\n", header->filename );
		
		mkdir_p( header->filename );
		
		FILE *fp = fopen( header->filename, "w+" );
		
		header_line_t *line;
		list_for_each_entry(line, &header->lines, node)
		{
			if( tag__is_type(line->tag))
			{
				print_types(line->cu, line->tag, true, fp);
			}
			else if( tag__is_variable(line->tag))
			{
				print_variables(line->cu, line->tag, true, fp );
			}
			else if( tag__is_function(line->tag))
			{
				print_functions(line->cu, tag__function(line->tag), true, fp );
			}
		}
		
		fclose(fp);
	}
}

static int cu__emit_tags(struct cu *cu)
{
	uint32_t i;
	struct tag *tag;
	struct function *function;
	FILE *fp;
	
	if(!strncmp(cu->name, "../", 3))
	{
		return 0;
	}
	
	mkdir_p(cu->name);
	
	printf( "SOURCE: %s\n", cu->name );
#if NO_WRITE_FILES
	fp = stdout;
#else
	fp = fopen(cu->name, "w+");
#endif

	fputs("/****************** Types:     ******************/\n", fp);
	cu__for_each_type(cu, i, tag) {
		print_types(cu, tag, false, fp);
	}
	
	fputs("\n/****************** Variables: ******************/\n", fp);
	cu__for_each_variable(cu, i, tag) {
		print_variables(cu, tag, false, fp);
	}

	fputs("\n/****************** Functions: ******************/\n", fp);
	conf.no_semicolon = true;
	cu__for_each_function(cu, i, function) {
		print_functions(cu, function, false, fp);
	}
	conf.no_semicolon = false;

	fclose(fp);

	return 0;
}

static enum load_steal_kind pdwtags_stealer(struct cu *cu,
					    struct conf_load *conf_load __maybe_unused,
					    void *thr_data __maybe_unused)
{
	cu__emit_tags(cu);
	
	return LSK__KEEPIT;
}

static struct conf_load pdwtags_conf_load = {
	.steal = pdwtags_stealer,
	.conf_fprintf = &conf,
	.extra_dbg_info = 1,
	.get_addr_info = 1,
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

	err = cus__load_file(cus, &pdwtags_conf_load, argv[remaining]);
	if (err == 0) {
		rc = EXIT_SUCCESS;
		headers_print();
		goto out;
	}

	cus__fprintf_load_files_err(cus, "pdwtags", argv + remaining, err, stderr);
out:
	cus__delete(cus);
	dwarves__exit();
	return rc;
}
