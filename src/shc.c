/* shc.c */

/**
 * Shell Script Compiler
 * Uses a custom Feistel cipher with per-compilation randomized
 * S-boxes, permutation tables, and round constants for encryption.
 * Licensed under GPL.
 * http://github.com/neurobin/shc
 */

static const char my_name[] = "shc";
static const char version[] = "Version 5.0.0";
static const char subject[] = "Generic Shell Script Compiler";
static const char cpright[] = "GNU GPL Version 3";
static const struct { const char * f, * s, * e; }
	provider = { "Md Jahidul", "Hamid", "<jahidulhamid@yahoo.com>" };          

/* 
static const struct { const char * f, * s, * e; }
	author = { "Francisco", "Garcia", "<frosal@fi.upm.es>" };
*/
/*This is the original author who first came up with this*/

static const char * copying[] = {
"Copying:",
"",
"    This program is free software; you can redistribute it and/or modify",
"    it under the terms of the GNU General Public License as published by",
"    the Free Software Foundation; either version 3 of the License, or",
"    (at your option) any later version.",
"",
"    This program is distributed in the hope that it will be useful,",
"    but WITHOUT ANY WARRANTY; without even the implied warranty of",
"    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the",
"    GNU General Public License for more details.",
"",
"    You should have received a copy of the GNU General Public License",
"    along with this program; if not, write to the Free Software",
"    @Neurobin, Dhaka, Bangladesh",
"",
"    Report problems and questions to:http://github.com/neurobin/shc",
"",
0};

static const char * abstract[] = {
"Abstract:",
"",
"    This tool generates a stripped binary executable version",
"    of the script specified at command line.",
"",
"    Binary version will be saved with a .x extension by default.",
"    You can specify output file name too with [-o filname] option.",
"",
"    You can specify expiration date [-e] too, after which binary will",
"    refuse to be executed, displaying \"[-m]\" instead.",
"",
"    You can compile whatever interpreted script, but valid [-i], [-x]",
"    and [-l] options must be given.",
"",
0};

static const char usage[] =
"Usage: shc [-e date] [-m addr] [-i iopt] [-x cmd] [-l lopt] [-o outfile] [-R host:port] [-d decoy] [-rvDSUHCAB2h] -f script";

static const char * help[] = {
"",
"    -e %s  Expiration date in dd/mm/yyyy format [none]",
"    -m %s  Message to display upon expiration [\"Please contact your provider\"]",
"    -f %s  File name of the script to compile",
"    -i %s  Inline option for the shell interpreter i.e: -e",
"    -x %s  eXec command, as a printf format i.e: exec('%s',@ARGV);",
"    -l %s  Last shell option i.e: --",
"    -o %s  output filename",
"    -r     Relax security. Make a redistributable binary",
"    -v     Verbose compilation",
"    -S     Switch ON setuid for root callable programs [OFF]",
"    -D     Switch ON debug exec calls [OFF]",
"    -U     Make binary untraceable [no]",
"    -H     Hardening : extra security protection [no]",
"           Require bourne shell (sh) and parameters are not supported",
"    -C     Display license and exit",
"    -A     Display abstract and exit",
"    -R %s  Remote key server host:port for key-split mode",
"    -d %s  Decoy script for plausible deniability (requires -R)",
"    -B     Compile for busybox",
"    -2     Use the system call mmap2",
"    -h     Display help and exit",
"",
"    Environment variables used:",
"    Name    Default  Usage",
"    CC      cc       C compiler command",
"    STRIP   strip    Strip command",
"    CFLAGS  <none>   C compiler flags",
"    LDFLAGS <none>   Linker flags",
"",
"    Please consult the shc man page.",
"",
0};

#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Forward declarations */
unsigned rand_mod(unsigned mod);
char rand_chr(void);

#define SIZE 4096

static char * file;
static char * file2;
static char   date[21];
static char * mail = "Please contact your provider jahidulhamid@yahoo.com";
static char   rlax[1];
static char * shll;
static char * inlo;
static char * xecc;
static char * lsto;
static char * opts;
static char * text;
static int verbose;
static char * remote_host;
static int    remote_port;
static const char SETUID_line[] =
"#define SETUID %d	/* Define as 1 to call setuid(0) at start of script */\n";
static int SETUID_flag = 0;
static const char DEBUGEXEC_line[] =
"#define DEBUGEXEC	%d	/* Define as 1 to debug exec calls */\n";
static int DEBUGEXEC_flag = 0;
static const char TRACEABLE_line[] =
"#define TRACEABLE	%d	/* Define as 1 to enable ptrace the executable */\n";
static int TRACEABLE_flag = 1;
static const char HARDENING_line[] =
"#define HARDENING	%d	/* Define as 1 to disable ptrace/dump the executable */\n";
static int HARDENING_flag = 0;
static const char MMAP2_line[] =
"#define MMAP2		%d	/* Define as 1 to use syscall mmap2 */\n";
static int MMAP2_flag = 0;
static const char BUSYBOXON_line[] =
"#define BUSYBOXON	%d	/* Define as 1 to enable work with busybox */\n";
static int BUSYBOXON_flag = 0;
static const char REMOTE_KEY_line[] =
"#define REMOTE_KEY	%d	/* Define as 1 to enable remote key-split */\n";
static int REMOTE_KEY_flag = 0;
static const char DENIABILITY_line[] =
"#define DENIABILITY	%d	/* Define as 1 to enable plausible deniability */\n";
static int DENIABILITY_flag = 0;
static char * decoy_file;
static char * decoy_text;

/* Cockatiel cipher parameters — per-compilation random */
#define CC_RACHIS_SEGS   3
#define CC_RACHIS_SEG_SZ 23
#define CC_VANE_SEGS     7
#define CC_VANE_SEG_SZ   60
#define CC_RACHIS_SZ     69   /* 3 x 23 */
#define CC_VANES_SZ      420  /* 7 x 60 */
#define CC_BLOCK_SZ      489  /* 69 + 420 */
#define CC_MAX_LAYERS    20
#define CC_NSBOX         8

struct cipher_params {
	unsigned char sbox[CC_NSBOX][256];                  /* 8 bijective S-boxes */
	unsigned char vane_perm[CC_VANE_SEGS][CC_VANE_SEG_SZ]; /* 7 byte permutations of {0..59} */
	unsigned char layer_const[CC_MAX_LAYERS][16];       /* per-layer constants */
	int nlayers;                                        /* 12-20 */
};

/* Runtime name generation */
struct rt_names {
	char cc_init[24];
	char cc_key_mix[24];
	char cc_crypt[24];
	char cc_mac[24];
	char cc_block[24];
	char cc_keysched[24];
	char cc_phase1[24];
	char cc_phase2[24];
	char cc_phase3[24];
	char cc_phase4[24];
	char key_with_file[24];
	char chkenv[24];
	char chkenv_end[24];
	char untraceable[24];
	char hardening[24];
	char xsh[24];
	char debugexec[24];
	char rmarg[24];
	char data_var[24];
	char env_prefix[8];
	char tmp_prefix[24];
	char seccomp_hardening[24];
	char shc_x_file[24];
	char rt_make[24];
	char hardrun[24];
	char gets_pname[24];
	char cc_key_var[24];
	char cc_ctr_var[24];
	char cc_buf_var[24];
	char cc_buf_pos_var[24];
	char cc_lkeys_var[24];
	char cc_sbox_var[24];
	char cc_vperm_var[24];
	char cc_lconst_var[24];
	char cc_nlayers_var[24];
	char xor_decode[24];
	char xor_prefix[8];
	char inline_getenv[24];
	char inline_setenv[24];
	char fetch_key[24];
	struct cipher_params cp;
};

static const char * rt_prefixes[] = {
	"cfg_", "buf_", "ctx_", "proc_", "sys_", "io_",
	"mem_", "val_", "net_", "res_", "hdl_", "obj_",
	NULL
};
static const char * rt_suffixes[] = {
	"data", "init", "run", "load", "sync", "exec",
	"open", "read", "step", "node", "item", "pool",
	NULL
};

static void gen_rt_name(char * out, int maxlen)
{
	int np = 0, ns = 0;
	const char ** p;
	char hex[8];
	for (p = rt_prefixes; *p; p++) np++;
	for (p = rt_suffixes; *p; p++) ns++;
	sprintf(hex, "%03x", rand_mod(0xfff));
	snprintf(out, maxlen, "%s%s%s", rt_prefixes[rand_mod(np)], rt_suffixes[rand_mod(ns)], hex);
}

static void generate_sbox(unsigned char sbox[256])
{
	int i, j;
	unsigned char tmp;
	/* Initialize identity */
	for (i = 0; i < 256; i++) sbox[i] = (unsigned char)i;
	/* Fisher-Yates shuffle */
	for (i = 255; i > 0; i--) {
		j = rand_mod(i + 1);
		tmp = sbox[i]; sbox[i] = sbox[j]; sbox[j] = tmp;
	}
}

static void init_rt_names(struct rt_names * n)
{
	int i, j;
	gen_rt_name(n->cc_init, sizeof(n->cc_init));
	gen_rt_name(n->cc_key_mix, sizeof(n->cc_key_mix));
	gen_rt_name(n->cc_crypt, sizeof(n->cc_crypt));
	gen_rt_name(n->cc_mac, sizeof(n->cc_mac));
	gen_rt_name(n->cc_block, sizeof(n->cc_block));
	gen_rt_name(n->cc_keysched, sizeof(n->cc_keysched));
	gen_rt_name(n->cc_phase1, sizeof(n->cc_phase1));
	gen_rt_name(n->cc_phase2, sizeof(n->cc_phase2));
	gen_rt_name(n->cc_phase3, sizeof(n->cc_phase3));
	gen_rt_name(n->cc_phase4, sizeof(n->cc_phase4));
	gen_rt_name(n->key_with_file, sizeof(n->key_with_file));
	gen_rt_name(n->chkenv, sizeof(n->chkenv));
	gen_rt_name(n->chkenv_end, sizeof(n->chkenv_end));
	gen_rt_name(n->untraceable, sizeof(n->untraceable));
	gen_rt_name(n->hardening, sizeof(n->hardening));
	gen_rt_name(n->xsh, sizeof(n->xsh));
	gen_rt_name(n->debugexec, sizeof(n->debugexec));
	gen_rt_name(n->rmarg, sizeof(n->rmarg));
	gen_rt_name(n->data_var, sizeof(n->data_var));
	gen_rt_name(n->seccomp_hardening, sizeof(n->seccomp_hardening));
	gen_rt_name(n->shc_x_file, sizeof(n->shc_x_file));
	gen_rt_name(n->rt_make, sizeof(n->rt_make));
	gen_rt_name(n->hardrun, sizeof(n->hardrun));
	gen_rt_name(n->gets_pname, sizeof(n->gets_pname));
	gen_rt_name(n->cc_key_var, sizeof(n->cc_key_var));
	gen_rt_name(n->cc_ctr_var, sizeof(n->cc_ctr_var));
	gen_rt_name(n->cc_buf_var, sizeof(n->cc_buf_var));
	gen_rt_name(n->cc_buf_pos_var, sizeof(n->cc_buf_pos_var));
	gen_rt_name(n->cc_lkeys_var, sizeof(n->cc_lkeys_var));
	gen_rt_name(n->cc_sbox_var, sizeof(n->cc_sbox_var));
	gen_rt_name(n->cc_vperm_var, sizeof(n->cc_vperm_var));
	gen_rt_name(n->cc_lconst_var, sizeof(n->cc_lconst_var));
	gen_rt_name(n->cc_nlayers_var, sizeof(n->cc_nlayers_var));
	gen_rt_name(n->xor_decode, sizeof(n->xor_decode));
	gen_rt_name(n->inline_getenv, sizeof(n->inline_getenv));
	gen_rt_name(n->inline_setenv, sizeof(n->inline_setenv));
	gen_rt_name(n->fetch_key, sizeof(n->fetch_key));
	/* xor prefix: 2-4 lowercase chars */
	{
		int len = 2 + rand_mod(3);
		for (i = 0; i < len; i++)
			n->xor_prefix[i] = 'a' + rand_mod(26);
		n->xor_prefix[len] = '\0';
	}
	/* env prefix: 2-4 lowercase chars */
	{
		int len = 2 + rand_mod(3);
		for (i = 0; i < len; i++)
			n->env_prefix[i] = 'a' + rand_mod(26);
		n->env_prefix[len] = '\0';
	}
	/* tmp prefix: random dotfile name */
	snprintf(n->tmp_prefix, sizeof(n->tmp_prefix), ".%08x", (unsigned)rand());
	/* Generate Cockatiel cipher parameters */
	n->cp.nlayers = 12 + rand_mod(9); /* 12-20 */
	/* 8 bijective S-boxes */
	for (i = 0; i < CC_NSBOX; i++)
		generate_sbox(n->cp.sbox[i]);
	/* 7 vane byte permutations of {0..59} via Fisher-Yates */
	for (i = 0; i < CC_VANE_SEGS; i++) {
		for (j = 0; j < CC_VANE_SEG_SZ; j++)
			n->cp.vane_perm[i][j] = (unsigned char)j;
		for (j = CC_VANE_SEG_SZ - 1; j > 0; j--) {
			int k = rand_mod(j + 1);
			unsigned char tmp = n->cp.vane_perm[i][j];
			n->cp.vane_perm[i][j] = n->cp.vane_perm[i][k];
			n->cp.vane_perm[i][k] = tmp;
		}
	}
	/* Per-layer constants (16 bytes each) */
	for (i = 0; i < n->cp.nlayers; i++)
		for (j = 0; j < 16; j++)
			n->cp.layer_const[i][j] = (unsigned char)rand_mod(256);
}

/* XOR-encode binary data and emit as static array with _z, _k defines */
static void emit_xor_binary(FILE *o, const char *varname, const void *data, int len)
{
	unsigned char xk = (unsigned char)(1 + rand_mod(254));
	const unsigned char *p = (const unsigned char *)data;
	int i;
	fprintf(o, "static unsigned char %s[] = {", varname);
	for (i = 0; i < len; i++) {
		if (i % 12 == 0) fprintf(o, "\n\t");
		fprintf(o, "0x%02x", p[i] ^ xk);
		if (i < len - 1) fprintf(o, ",");
	}
	fprintf(o, "};\n");
	fprintf(o, "#define %s_k 0x%02x\n", varname, xk);
	fprintf(o, "#define %s_z %d\n", varname, len);
}

/* XOR-encode a string literal and emit as static array */
static void emit_xor_string(FILE *o, const char *varname, const char *str)
{
	unsigned char xk = (unsigned char)(1 + rand_mod(254));
	int len = strlen(str);
	int i;
	fprintf(o, "static unsigned char %s[] = {", varname);
	for (i = 0; i <= len; i++) {
		if (i % 12 == 0) fprintf(o, "\n\t");
		fprintf(o, "0x%02x", (unsigned char)str[i] ^ xk);
		if (i < len) fprintf(o, ",");
	}
	fprintf(o, "};\n");
	fprintf(o, "#define %s_k 0x%02x\n", varname, xk);
	fprintf(o, "#define %s_n %d\n", varname, len + 1);
}

/* Decode macro for XOR strings — decodes in place, use, then re-encode */
static void emit_xor_decode_func(FILE *o, const char *fname)
{
	fprintf(o, "static void %s(unsigned char *s, int n, unsigned char k) {\n", fname);
	fprintf(o, "\tint i; for(i=0;i<n;i++) s[i]^=k;\n");
	fprintf(o, "}\n");
}

static void emit_runtime(FILE *o, struct rt_names *n)
{
	/* HARDENING: shc_x shared library source */
	fprintf(o, "\n#if HARDENING\n");
	fprintf(o, "static const char * _hx[] = {\n");
	fprintf(o, "\"/*\",\n");
	fprintf(o, "\" * Replace ******** with secret read from fd 21\",\n");
	fprintf(o, "\" * gcc -Wall -fpic -shared -o _hx.so _hx.c -ldl\",\n");
	fprintf(o, "\" */\",\n");
	fprintf(o, "\"\",\n");
	fprintf(o, "\"#define _GNU_SOURCE\",\n");
	fprintf(o, "\"#define PLACEHOLDER \\\"********\\\"\",\n");
	fprintf(o, "\"#include <dlfcn.h>\",\n");
	fprintf(o, "\"#include <stdlib.h>\",\n");
	fprintf(o, "\"#include <string.h>\",\n");
	fprintf(o, "\"#include <unistd.h>\",\n");
	fprintf(o, "\"#include <stdio.h>\",\n");
	fprintf(o, "\"#include <signal.h>\",\n");
	fprintf(o, "\"\",\n");
	fprintf(o, "\"static char secret[128000];\",\n");
	fprintf(o, "\"typedef int (*pfi)(int, char **, char **);\",\n");
	fprintf(o, "\"static pfi real_main;\",\n");
	fprintf(o, "\"\",\n");
	fprintf(o, "\"char **copyargs(int argc, char** argv){\",\n");
	fprintf(o, "\"    char **newargv = malloc((argc+1)*sizeof(*argv));\",\n");
	fprintf(o, "\"    char *from,*to;\",\n");
	fprintf(o, "\"    int i,len;\",\n");
	fprintf(o, "\"    for(i = 0; i<argc; i++){\",\n");
	fprintf(o, "\"        from = argv[i];\",\n");
	fprintf(o, "\"        len = strlen(from)+1;\",\n");
	fprintf(o, "\"        to = malloc(len);\",\n");
	fprintf(o, "\"        memcpy(to,from,len);\",\n");
	fprintf(o, "\"        memset(from,'\\\\0',len);\",\n");
	fprintf(o, "\"        newargv[i] = to;\",\n");
	fprintf(o, "\"        argv[i] = 0;\",\n");
	fprintf(o, "\"    }\",\n");
	fprintf(o, "\"    newargv[argc] = 0;\",\n");
	fprintf(o, "\"    return newargv;\",\n");
	fprintf(o, "\"}\",\n");
	fprintf(o, "\"\",\n");
	fprintf(o, "\"static int mymain(int argc, char** argv, char** env) {\",\n");
	fprintf(o, "\"    return real_main(argc, copyargs(argc,argv), env);\",\n");
	fprintf(o, "\"}\",\n");
	fprintf(o, "\"\",\n");
	fprintf(o, "\"int __libc_start_main(int (*main) (int, char**, char**),\",\n");
	fprintf(o, "\"                      int argc,\",\n");
	fprintf(o, "\"                      char **argv,\",\n");
	fprintf(o, "\"                      void (*init) (void),\",\n");
	fprintf(o, "\"                      void (*fini)(void),\",\n");
	fprintf(o, "\"                      void (*rtld_fini)(void),\",\n");
	fprintf(o, "\"                      void (*stack_end)){\",\n");
	fprintf(o, "\"    static int (*real___libc_start_main)() = NULL;\",\n");
	fprintf(o, "\"    int n;\",\n");
	fprintf(o, "\"    if (!real___libc_start_main) {\",\n");
	fprintf(o, "\"        real___libc_start_main = dlsym(RTLD_NEXT, \\\"__libc_start_main\\\");\",\n");
	fprintf(o, "\"        if (!real___libc_start_main) abort();\",\n");
	fprintf(o, "\"    }\",\n");
	fprintf(o, "\"    n = read(21, secret, sizeof(secret));\",\n");
	fprintf(o, "\"    if (n > 0) {\",\n");
	fprintf(o, "\"      int i;\",\n");
	fprintf(o, "\"    if (secret[n - 1] == '\\\\n') secret[--n] = '\\\\0';\",\n");
	fprintf(o, "\"    for (i = 1; i < argc; i++)\",\n");
	fprintf(o, "\"        if (strcmp(argv[i], PLACEHOLDER) == 0)\",\n");
	fprintf(o, "\"          argv[i] = secret;\",\n");
	fprintf(o, "\"    }\",\n");
	fprintf(o, "\"    real_main = main;\",\n");
	fprintf(o, "\"    return real___libc_start_main(mymain, argc, argv, init, fini, rtld_fini, stack_end);\",\n");
	fprintf(o, "\"}\",\n");
	fprintf(o, "\"\",\n");
	fprintf(o, "0};\n");
	fprintf(o, "#endif /* HARDENING */\n\n");

	/* Includes */
	fprintf(o, "#define _GNU_SOURCE\n");
	fprintf(o, "#include <sys/stat.h>\n");
	fprintf(o, "#include <sys/types.h>\n");
	fprintf(o, "#include <errno.h>\n");
	fprintf(o, "#include <stdio.h>\n");
	fprintf(o, "#include <stdlib.h>\n");
	fprintf(o, "#include <string.h>\n");
	fprintf(o, "#include <time.h>\n");
	fprintf(o, "#include <sys/time.h>\n");
	fprintf(o, "#include <unistd.h>\n");
	fprintf(o, "#include <dlfcn.h>\n");
	fprintf(o, "#ifdef __linux__\n");
	fprintf(o, "#include <sys/syscall.h>\n");
	fprintf(o, "#endif\n\n");

	/* Cockatiel cipher implementation with randomized names */
	fprintf(o, "static unsigned char %s[32];\n", n->cc_key_var);
	fprintf(o, "static unsigned int  %s;\n", n->cc_ctr_var);
	fprintf(o, "static unsigned char %s[%d];\n", n->cc_buf_var, CC_BLOCK_SZ);
	fprintf(o, "static int           %s;\n", n->cc_buf_pos_var);
	fprintf(o, "static unsigned char %s[%d][16];\n", n->cc_lkeys_var, n->cp.nlayers);
	/* Embed 8 S-boxes as static arrays */
	{
		int s, b;
		for (s = 0; s < CC_NSBOX; s++) {
			fprintf(o, "static unsigned char %s%d[256] = {", n->cc_sbox_var, s);
			for (b = 0; b < 256; b++) {
				if (b % 16 == 0) fprintf(o, "\n\t");
				fprintf(o, "0x%02x", n->cp.sbox[s][b]);
				if (b < 255) fprintf(o, ",");
			}
			fprintf(o, "\n};\n");
		}
	}
	/* Embed 7 vane permutation tables */
	{
		int v, b;
		for (v = 0; v < CC_VANE_SEGS; v++) {
			fprintf(o, "static unsigned char %s%d[%d] = {", n->cc_vperm_var, v, CC_VANE_SEG_SZ);
			for (b = 0; b < CC_VANE_SEG_SZ; b++) {
				if (b % 16 == 0) fprintf(o, "\n\t");
				fprintf(o, "%d", n->cp.vane_perm[v][b]);
				if (b < CC_VANE_SEG_SZ - 1) fprintf(o, ",");
			}
			fprintf(o, "\n};\n");
		}
	}
	/* Embed layer constants */
	{
		int r, b;
		fprintf(o, "static unsigned char %s[%d][16] = {\n", n->cc_lconst_var, n->cp.nlayers);
		for (r = 0; r < n->cp.nlayers; r++) {
			fprintf(o, "\t{");
			for (b = 0; b < 16; b++) {
				fprintf(o, "0x%02x", n->cp.layer_const[r][b]);
				if (b < 15) fprintf(o, ",");
			}
			fprintf(o, "}%s\n", r < n->cp.nlayers - 1 ? "," : "");
		}
		fprintf(o, "};\n");
	}
	fprintf(o, "static int %s = %d;\n\n", n->cc_nlayers_var, n->cp.nlayers);

	/* cc_keysched — key schedule: 32-byte key -> N x 16-byte layer keys */
	{
		char kv[24], kt[24];
		gen_rt_name(kv, sizeof(kv));
		gen_rt_name(kt, sizeof(kt));
		fprintf(o, "static void %s(void)\n{\n", n->cc_keysched);
		fprintf(o, "\tunsigned char %s[32];\n", kt);
		fprintf(o, "\tint %s, _j;\n", kv);
		fprintf(o, "\tfor(_j=0;_j<32;_j++) %s[_j]=%s[_j];\n", kt, n->cc_key_var);
		fprintf(o, "\tfor(%s=0;%s<%s;%s++) {\n", kv,kv, n->cc_nlayers_var, kv);
		fprintf(o, "\t\tunsigned char _sv[11];\n");
		fprintf(o, "\t\t%s[0]^=(unsigned char)%s;\n", kt, kv);
		fprintf(o, "\t\t%s[1]^=(unsigned char)(%s*137);\n", kt, kv);
		/* S-box pass */
		fprintf(o, "\t\tfor(_j=0;_j<32;_j++) {\n");
		fprintf(o, "\t\t\tswitch(_j%%%d) {\n", CC_NSBOX);
		{ int s; for (s = 0; s < CC_NSBOX; s++)
			fprintf(o, "\t\t\tcase %d: %s[_j]=%s%d[%s[_j]]; break;\n", s, kt, n->cc_sbox_var, s, kt);
		}
		fprintf(o, "\t\t\t}\n");
		fprintf(o, "\t\t}\n");
		/* Rotate left by 11 */
		fprintf(o, "\t\tfor(_j=0;_j<11;_j++) _sv[_j]=%s[_j];\n", kt);
		fprintf(o, "\t\tfor(_j=0;_j<21;_j++) %s[_j]=%s[_j+11];\n", kt, kt);
		fprintf(o, "\t\tfor(_j=0;_j<11;_j++) %s[21+_j]=_sv[_j];\n", kt);
		/* Cross-byte mixing */
		fprintf(o, "\t\tfor(_j=0;_j<32;_j++) %s[_j]^=%s[(_j+17)%%32];\n", kt, kt);
		/* S-box pass 2: sbox[(j+4)%8] */
		fprintf(o, "\t\tfor(_j=0;_j<32;_j++) {\n");
		fprintf(o, "\t\t\tswitch((_j+4)%%%d) {\n", CC_NSBOX);
		{ int s; for (s = 0; s < CC_NSBOX; s++)
			fprintf(o, "\t\t\tcase %d: %s[_j]=%s%d[%s[_j]]; break;\n", s, kt, n->cc_sbox_var, s, kt);
		}
		fprintf(o, "\t\t\t}\n");
		fprintf(o, "\t\t}\n");
		/* XOR-fold into 16-byte layer key */
		fprintf(o, "\t\tfor(_j=0;_j<16;_j++) %s[%s][_j]=%s[_j]^%s[_j+16];\n",
			n->cc_lkeys_var, kv, kt, kt);
		fprintf(o, "\t}\n");
		fprintf(o, "}\n\n");
	}

	/* cc_phase1 — Barb Separation */
	{
		char pr[24], pv[24];
		gen_rt_name(pr, sizeof(pr));
		gen_rt_name(pv, sizeof(pv));
		fprintf(o, "static void %s(unsigned char *%s, unsigned char *%s, const unsigned char *_elc, int _L)\n{\n",
			n->cc_phase1, pr, pv);
		fprintf(o, "\tint _i, _b, _t;\n");
		fprintf(o, "\tfor(_i=0;_i<%d;_i++) {\n", CC_RACHIS_SZ);
		fprintf(o, "\t\tfor(_b=0;_b<8;_b++) {\n");
		fprintf(o, "\t\t\t_t=(_i*8+_b)%%%d;\n", CC_VANES_SZ);
		fprintf(o, "\t\t\tif((%s[_i]>>_b)&1) {\n", pr);
		fprintf(o, "\t\t\t\tswitch((_i+_L)%%%d) {\n", CC_NSBOX);
		{ int s; for (s = 0; s < CC_NSBOX; s++)
			fprintf(o, "\t\t\t\tcase %d: %s[_t]=%s%d[%s[_t]]; break;\n", s, pv, n->cc_sbox_var, s, pv);
		}
		fprintf(o, "\t\t\t\t}\n");
		fprintf(o, "\t\t\t} else {\n");
		fprintf(o, "\t\t\t\t%s[_t]^=_elc[(_i+_b)%%16];\n", pv);
		fprintf(o, "\t\t\t}\n");
		fprintf(o, "\t\t}\n");
		fprintf(o, "\t}\n");
		fprintf(o, "}\n\n");
	}

	/* cc_phase2 — Interlocking */
	{
		char pr[24], pv[24];
		gen_rt_name(pr, sizeof(pr));
		gen_rt_name(pv, sizeof(pv));
		fprintf(o, "static void %s(unsigned char *%s, unsigned char *%s, int _L)\n{\n",
			n->cc_phase2, pr, pv);
		fprintf(o, "\tint _k, _j, _src, _dst, _idx;\n");
		fprintf(o, "\tunsigned char _rv;\n");
		fprintf(o, "\tfor(_k=0;_k<%d;_k++) {\n", CC_RACHIS_SEGS);
		fprintf(o, "\t\t_rv=%s[_k*%d+(_L%%%d)];\n", pr, CC_RACHIS_SEG_SZ, CC_RACHIS_SEG_SZ);
		fprintf(o, "\t\t_src=_rv%%%d;\n", CC_VANE_SEGS);
		fprintf(o, "\t\t_dst=(_rv/%d+1+_k)%%%d;\n", CC_VANE_SEGS, CC_VANE_SEGS);
		fprintf(o, "\t\tif(_dst==_src) _dst=(_dst+1)%%%d;\n", CC_VANE_SEGS);
		fprintf(o, "\t\tfor(_j=0;_j<%d;_j++) {\n", CC_VANE_SEG_SZ);
		fprintf(o, "\t\t\tswitch(_src) {\n");
		{ int v; for (v = 0; v < CC_VANE_SEGS; v++)
			fprintf(o, "\t\t\tcase %d: _idx=%s%d[_j]; break;\n", v, n->cc_vperm_var, v);
		}
		fprintf(o, "\t\t\tdefault: _idx=_j;\n");
		fprintf(o, "\t\t\t}\n");
		/* S-box lookup with switch */
		fprintf(o, "\t\t\tswitch((_k*2+1)%%%d) {\n", CC_NSBOX);
		{ int s; for (s = 0; s < CC_NSBOX; s++)
			fprintf(o, "\t\t\tcase %d: %s[_dst*%d+_j]^=%s%d[%s[_src*%d+_idx]]; break;\n",
				s, pv, CC_VANE_SEG_SZ, n->cc_sbox_var, s, pv, CC_VANE_SEG_SZ);
		}
		fprintf(o, "\t\t\t}\n");
		fprintf(o, "\t\t}\n");
		fprintf(o, "\t}\n");
		fprintf(o, "}\n\n");
	}

	/* cc_phase3 — Afterfeather */
	{
		char pv[24];
		gen_rt_name(pv, sizeof(pv));
		fprintf(o, "static void %s(unsigned char *%s, int _L)\n{\n",
			n->cc_phase3, pv);
		fprintf(o, "\tint _i, _j, _nx;\n");
		fprintf(o, "\tunsigned char _tmp[%d];\n", CC_VANE_SEG_SZ);
		fprintf(o, "\tfor(_i=0;_i<%d;_i++) {\n", CC_VANE_SEGS);
		fprintf(o, "\t\t_nx=(_i+1)%%%d;\n", CC_VANE_SEGS);
		/* S-box XOR into next vane */
		fprintf(o, "\t\tfor(_j=0;_j<%d;_j++) {\n", CC_VANE_SEG_SZ);
		fprintf(o, "\t\t\tswitch((_i+4)%%%d) {\n", CC_NSBOX);
		{ int s; for (s = 0; s < CC_NSBOX; s++)
			fprintf(o, "\t\t\tcase %d: %s[_nx*%d+_j]^=%s%d[%s[_i*%d+_j]]; break;\n",
				s, pv, CC_VANE_SEG_SZ, n->cc_sbox_var, s, pv, CC_VANE_SEG_SZ);
		}
		fprintf(o, "\t\t\t}\n");
		fprintf(o, "\t\t}\n");
		/* Vane byte permutation */
		fprintf(o, "\t\tfor(_j=0;_j<%d;_j++) _tmp[_j]=%s[_i*%d+_j];\n", CC_VANE_SEG_SZ, pv, CC_VANE_SEG_SZ);
		fprintf(o, "\t\tswitch(_i) {\n");
		{ int v; for (v = 0; v < CC_VANE_SEGS; v++)
			fprintf(o, "\t\tcase %d: for(_j=0;_j<%d;_j++) %s[_i*%d+_j]=_tmp[%s%d[_j]]; break;\n",
				v, CC_VANE_SEG_SZ, pv, CC_VANE_SEG_SZ, n->cc_vperm_var, v);
		}
		fprintf(o, "\t\t}\n");
		fprintf(o, "\t}\n");
		fprintf(o, "}\n\n");
	}

	/* cc_phase4 — Rachis Update */
	{
		char pr[24], pv[24];
		gen_rt_name(pr, sizeof(pr));
		gen_rt_name(pv, sizeof(pv));
		fprintf(o, "static void %s(unsigned char *%s, unsigned char *%s, const unsigned char *_elc, int _L)\n{\n",
			n->cc_phase4, pr, pv);
		fprintf(o, "\tint _k, _j, _fv;\n");
		fprintf(o, "\tfor(_k=0;_k<%d;_k++) {\n", CC_RACHIS_SEGS);
		fprintf(o, "\t\t_fv=(_k+_L)%%%d;\n", CC_VANE_SEGS);
		fprintf(o, "\t\tfor(_j=0;_j<%d;_j++) {\n", CC_RACHIS_SEG_SZ);
		fprintf(o, "\t\t\tswitch((_k+6)%%%d) {\n", CC_NSBOX);
		{ int s; for (s = 0; s < CC_NSBOX; s++)
			fprintf(o, "\t\t\tcase %d: %s[_k*%d+_j]^=%s%d[%s[_fv*%d+(_j*2)%%%d]]; break;\n",
				s, pr, CC_RACHIS_SEG_SZ, n->cc_sbox_var, s, pv, CC_VANE_SEG_SZ, CC_VANE_SEG_SZ);
		}
		fprintf(o, "\t\t\t}\n");
		fprintf(o, "\t\t\t%s[_k*%d+_j]=(%s[_k*%d+_j]+_elc[(_k*8+_j)%%16])&0xFF;\n",
			pr, CC_RACHIS_SEG_SZ, pr, CC_RACHIS_SEG_SZ);
		fprintf(o, "\t\t}\n");
		fprintf(o, "\t}\n");
		fprintf(o, "}\n\n");
	}

	/* cc_block — full block encrypt (489 bytes) */
	{
		char bi[24], bo[24];
		gen_rt_name(bi, sizeof(bi));
		gen_rt_name(bo, sizeof(bo));
		fprintf(o, "static void %s(unsigned char %s[%d], unsigned char %s[%d])\n{\n",
			n->cc_block, bi, CC_BLOCK_SZ, bo, CC_BLOCK_SZ);
		fprintf(o, "\tunsigned char _blk[%d], _elc[16];\n", CC_BLOCK_SZ);
		fprintf(o, "\tint _L, _j;\n");
		fprintf(o, "\tmemcpy(_blk, %s, %d);\n", bi, CC_BLOCK_SZ);
		fprintf(o, "\tfor(_L=0;_L<%s;_L++) {\n", n->cc_nlayers_var);
		fprintf(o, "\t\tfor(_j=0;_j<16;_j++) _elc[_j]=%s[_L][_j]^%s[_L][_j];\n",
			n->cc_lconst_var, n->cc_lkeys_var);
		fprintf(o, "\t\t%s(_blk, _blk+%d, _elc, _L);\n", n->cc_phase1, CC_RACHIS_SZ);
		fprintf(o, "\t\t%s(_blk, _blk+%d, _L);\n", n->cc_phase2, CC_RACHIS_SZ);
		fprintf(o, "\t\t%s(_blk+%d, _L);\n", n->cc_phase3, CC_RACHIS_SZ);
		fprintf(o, "\t\t%s(_blk, _blk+%d, _elc, _L);\n", n->cc_phase4, CC_RACHIS_SZ);
		fprintf(o, "\t}\n");
		fprintf(o, "\tmemcpy(%s, _blk, %d);\n", bo, CC_BLOCK_SZ);
		fprintf(o, "}\n\n");
	}

	/* cc_init */
	fprintf(o, "static void %s(void)\n{\n", n->cc_init);
	fprintf(o, "\tmemset(%s, 0, 32);\n", n->cc_key_var);
	fprintf(o, "\t%s = 0;\n", n->cc_ctr_var);
	fprintf(o, "\t%s = %d;\n", n->cc_buf_pos_var, CC_BLOCK_SZ);
	fprintf(o, "}\n\n");

	/* cc_key_mix */
	fprintf(o, "static void %s(void * str, int len)\n{\n", n->cc_key_mix);
	fprintf(o, "\tunsigned char * ptr = (unsigned char *)str;\n");
	fprintf(o, "\tint i;\n");
	fprintf(o, "\tfor (i = 0; i < len; i++)\n");
	fprintf(o, "\t\t%s[i %% 32] ^= ptr[i];\n", n->cc_key_var);
	fprintf(o, "\t%s();\n", n->cc_keysched);
	fprintf(o, "\t{\n");
	fprintf(o, "\t\tunsigned char _b1[%d], _b2[%d], _o1[%d], _o2[%d];\n",
		CC_BLOCK_SZ, CC_BLOCK_SZ, CC_BLOCK_SZ, CC_BLOCK_SZ);
	fprintf(o, "\t\tfor(i=0;i<%d;i++){_b1[i]=i&0xFF;_b2[i]=(%d-1-i)&0xFF;}\n", CC_BLOCK_SZ, CC_BLOCK_SZ);
	fprintf(o, "\t\t%s(_b1, _o1);\n", n->cc_block);
	fprintf(o, "\t\t%s(_b2, _o2);\n", n->cc_block);
	fprintf(o, "\t\tmemcpy(%s, _o1, 16);\n", n->cc_key_var);
	fprintf(o, "\t\tmemcpy(%s + 16, _o2, 16);\n", n->cc_key_var);
	fprintf(o, "\t}\n");
	fprintf(o, "\t%s();\n", n->cc_keysched);
	fprintf(o, "\t%s = 0;\n", n->cc_ctr_var);
	fprintf(o, "\t%s = %d;\n", n->cc_buf_pos_var, CC_BLOCK_SZ);
	fprintf(o, "}\n\n");

	/* cc_crypt — CTR mode with 489-byte blocks */
	fprintf(o, "static void %s(void * str, int len)\n{\n", n->cc_crypt);
	fprintf(o, "\tunsigned char * ptr = (unsigned char *)str;\n");
	fprintf(o, "\tint i;\n");
	fprintf(o, "\tfor (i = 0; i < len; i++) {\n");
	fprintf(o, "\t\tif (%s >= %d) {\n", n->cc_buf_pos_var, CC_BLOCK_SZ);
	fprintf(o, "\t\t\tunsigned char _cb[%d];\n", CC_BLOCK_SZ);
	fprintf(o, "\t\t\tmemset(_cb, 0, %d);\n", CC_BLOCK_SZ);
	fprintf(o, "\t\t\t_cb[0]=(unsigned char)(%s);\n", n->cc_ctr_var);
	fprintf(o, "\t\t\t_cb[1]=(unsigned char)(%s>>8);\n", n->cc_ctr_var);
	fprintf(o, "\t\t\t_cb[2]=(unsigned char)(%s>>16);\n", n->cc_ctr_var);
	fprintf(o, "\t\t\t_cb[3]=(unsigned char)(%s>>24);\n", n->cc_ctr_var);
	fprintf(o, "\t\t\t_cb[4]=(unsigned char)(~%s);\n", n->cc_ctr_var);
	fprintf(o, "\t\t\t_cb[5]=(unsigned char)(~%s>>8);\n", n->cc_ctr_var);
	fprintf(o, "\t\t\t_cb[6]=(unsigned char)(~%s>>16);\n", n->cc_ctr_var);
	fprintf(o, "\t\t\t_cb[7]=(unsigned char)(~%s>>24);\n", n->cc_ctr_var);
	fprintf(o, "\t\t\t%s++;\n", n->cc_ctr_var);
	fprintf(o, "\t\t\t%s(_cb, %s);\n", n->cc_block, n->cc_buf_var);
	fprintf(o, "\t\t\t%s = 0;\n", n->cc_buf_pos_var);
	fprintf(o, "\t\t}\n");
	fprintf(o, "\t\tptr[i] ^= %s[%s++];\n", n->cc_buf_var, n->cc_buf_pos_var);
	fprintf(o, "\t}\n");
	fprintf(o, "}\n\n");

	/* cc_mac — CBC-MAC producing 16-byte tag (489-byte accumulator, XOR-folded) */
	fprintf(o, "static void %s(void * str, int len, unsigned char *tag)\n{\n", n->cc_mac);
	fprintf(o, "\tunsigned char *ptr = (unsigned char *)str;\n");
	fprintf(o, "\tunsigned char _acc[%d], _enc[%d], _sk[32];\n", CC_BLOCK_SZ, CC_BLOCK_SZ);
	fprintf(o, "\tunsigned char _slk[%d][16];\n", n->cp.nlayers);
	fprintf(o, "\tunsigned int _sc; int _sp, _i, _pos;\n");
	/* Save state */
	fprintf(o, "\tmemcpy(_sk, %s, 32);\n", n->cc_key_var);
	fprintf(o, "\t_sc = %s; _sp = %s;\n", n->cc_ctr_var, n->cc_buf_pos_var);
	fprintf(o, "\tmemcpy(_slk, %s, sizeof(_slk));\n", n->cc_lkeys_var);
	/* Differentiate MAC key */
	fprintf(o, "\t%s[0] ^= 0xff;\n", n->cc_key_var);
	fprintf(o, "\t%s();\n", n->cc_keysched);
	/* CBC-MAC with 489-byte blocks */
	fprintf(o, "\tmemset(_acc, 0, %d);\n", CC_BLOCK_SZ);
	fprintf(o, "\t_pos = 0;\n");
	fprintf(o, "\tfor (_i = 0; _i < len; _i++) {\n");
	fprintf(o, "\t\t_acc[_pos++] ^= ptr[_i];\n");
	fprintf(o, "\t\tif (_pos == %d) {\n", CC_BLOCK_SZ);
	fprintf(o, "\t\t\t%s(_acc, _enc);\n", n->cc_block);
	fprintf(o, "\t\t\tmemcpy(_acc, _enc, %d);\n", CC_BLOCK_SZ);
	fprintf(o, "\t\t\t_pos = 0;\n");
	fprintf(o, "\t\t}\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\tif (_pos > 0) {\n");
	fprintf(o, "\t\t%s(_acc, _enc);\n", n->cc_block);
	fprintf(o, "\t\tmemcpy(_acc, _enc, %d);\n", CC_BLOCK_SZ);
	fprintf(o, "\t}\n");
	/* XOR-fold 489 -> 16 bytes */
	fprintf(o, "\tmemset(tag, 0, 16);\n");
	fprintf(o, "\tfor(_i=0;_i<%d;_i++) tag[_i%%16]^=_acc[_i];\n", CC_BLOCK_SZ);
	/* Restore state */
	fprintf(o, "\tmemcpy(%s, _sk, 32);\n", n->cc_key_var);
	fprintf(o, "\t%s = _sc; %s = _sp;\n", n->cc_ctr_var, n->cc_buf_pos_var);
	fprintf(o, "\tmemcpy(%s, _slk, sizeof(_slk));\n", n->cc_lkeys_var);
	fprintf(o, "}\n\n");

	/* inline getenv helper — searches environ directly, removes getenv from PLT */
	fprintf(o, "static char *%s(const char *n) {\n", n->inline_getenv);
	fprintf(o, "\textern char **environ;\n");
	fprintf(o, "\tchar **e; int l = 0;\n");
	fprintf(o, "\twhile (n[l]) l++;\n");
	fprintf(o, "\tfor (e = environ; e && *e; e++) {\n");
	fprintf(o, "\t\tint i, m = 1;\n");
	fprintf(o, "\t\tfor (i = 0; i < l; i++) if ((*e)[i] != n[i]) { m = 0; break; }\n");
	fprintf(o, "\t\tif (m && (*e)[l] == '=') return &(*e)[l+1];\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\treturn 0;\n");
	fprintf(o, "}\n\n");

	/* inline setenv helper — manipulates environ directly, removes setenv/dlsym from PLT */
	fprintf(o, "static void %s(const char *k, const char *v) {\n", n->inline_setenv);
	fprintf(o, "\textern char **environ;\n");
	fprintf(o, "\tint kl = 0, vl = 0, cnt = 0;\n");
	fprintf(o, "\twhile (k[kl]) kl++;\n");
	fprintf(o, "\twhile (v[vl]) vl++;\n");
	fprintf(o, "\tchar **e;\n");
	fprintf(o, "\tfor (e = environ; *e; e++) {\n");
	fprintf(o, "\t\tint i, m = 1;\n");
	fprintf(o, "\t\tfor (i = 0; i < kl; i++) if ((*e)[i] != k[i]) { m = 0; break; }\n");
	fprintf(o, "\t\tif (m && (*e)[kl] == '=') {\n");
	fprintf(o, "\t\t\tchar *nv = malloc(kl + 1 + vl + 1);\n");
	fprintf(o, "\t\t\tmemcpy(nv, k, kl); nv[kl] = '=';\n");
	fprintf(o, "\t\t\tmemcpy(nv+kl+1, v, vl+1);\n");
	fprintf(o, "\t\t\t*e = nv;\n");
	fprintf(o, "\t\t\treturn;\n");
	fprintf(o, "\t\t}\n");
	fprintf(o, "\t\tcnt++;\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\t{\n");
	fprintf(o, "\t\tchar *nv = malloc(kl + 1 + vl + 1);\n");
	fprintf(o, "\t\tmemcpy(nv, k, kl); nv[kl] = '=';\n");
	fprintf(o, "\t\tmemcpy(nv+kl+1, v, vl+1);\n");
	fprintf(o, "\t\tchar **ne = malloc((cnt + 2) * sizeof(char *));\n");
	fprintf(o, "\t\tmemcpy(ne, environ, cnt * sizeof(char *));\n");
	fprintf(o, "\t\tne[cnt] = nv; ne[cnt+1] = 0;\n");
	fprintf(o, "\t\tenviron = ne;\n");
	fprintf(o, "\t}\n");
	fprintf(o, "}\n\n");

	/* HARDENING section */
	fprintf(o, "#if HARDENING\n\n");
	fprintf(o, "#include <sys/ptrace.h>\n");
	fprintf(o, "#include <sys/wait.h>\n");
	fprintf(o, "#include <signal.h>\n");
	fprintf(o, "#include <sys/prctl.h>\n");
	fprintf(o, "#define PR_SET_PTRACER 0x59616d61\n\n");

	fprintf(o, "#include <stddef.h>\n");
	fprintf(o, "#include <sys/syscall.h>\n");
	fprintf(o, "#include <sys/socket.h>\n");
	fprintf(o, "#include <linux/filter.h>\n");
	fprintf(o, "#include <linux/seccomp.h>\n");
	fprintf(o, "#include <linux/audit.h>\n\n");

	fprintf(o, "#define ArchField offsetof(struct seccomp_data, arch)\n");
	fprintf(o, "#define Allow(syscall) \\\n");
	fprintf(o, "    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_##syscall, 0, 1), \\\n");
	fprintf(o, "    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)\n\n");

	fprintf(o, "struct sock_filter filter[] = {\n");
	fprintf(o, "    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ArchField),\n");
	fprintf(o, "    BPF_JUMP( BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),\n");
	fprintf(o, "    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),\n");
	fprintf(o, "    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),\n");
	fprintf(o, "    Allow(exit_group),\n");
	fprintf(o, "    Allow(brk),\n");
	fprintf(o, "#if MMAP2\n");
	fprintf(o, "    Allow(mmap2),\n");
	fprintf(o, "#else\n");
	fprintf(o, "    Allow(mmap),\n");
	fprintf(o, "#endif\n");
	fprintf(o, "    Allow(munmap),\n");
	fprintf(o, "    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),\n");
	fprintf(o, "};\n");
	fprintf(o, "struct sock_fprog filterprog = {\n");
	fprintf(o, "    .len = sizeof(filter)/sizeof(filter[0]),\n");
	fprintf(o, "    .filter = filter\n");
	fprintf(o, "};\n\n");

	fprintf(o, "void %s() {\n", n->seccomp_hardening);
	fprintf(o, "    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { exit(1); }\n");
	fprintf(o, "    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filterprog) == -1) { exit(1); }\n");
	fprintf(o, "}\n\n");

	/* shc_x_file with randomized tmp paths */
	fprintf(o, "void %s() {\n", n->shc_x_file);
	fprintf(o, "    FILE *fp;\n");
	fprintf(o, "    int line = 0;\n");
	fprintf(o, "    if ((fp = fopen(\"/tmp/%s.c\", \"w\")) == NULL) {exit(1);}\n", n->tmp_prefix);
	fprintf(o, "    for (line = 0; _hx[line]; line++) fprintf(fp, \"%%s\\n\", _hx[line]);\n");
	fprintf(o, "    fflush(fp); fclose(fp);\n");
	fprintf(o, "}\n\n");

	fprintf(o, "int %s() {\n", n->rt_make);
	fprintf(o, "\tchar * cc;\n");
	fprintf(o, "    char cmd[4096];\n");
	fprintf(o, "\tcc = %s(\"CC\");\n", n->inline_getenv);
	fprintf(o, "\tif (!cc) cc = \"cc\";\n");
	fprintf(o, "\tsprintf(cmd, \"%%s %%s -o %%s %%s\", cc, \"-Wall -fpic -shared\", \"/tmp/%s.so\", \"/tmp/%s.c -ldl\");\n", n->tmp_prefix, n->tmp_prefix);
	fprintf(o, "\tif (system(cmd)) {remove(\"/tmp/%s.c\"); return -1;}\n", n->tmp_prefix);
	fprintf(o, "\tremove(\"/tmp/%s.c\"); return 0;\n", n->tmp_prefix);
	fprintf(o, "}\n\n");

	/* hardrun with Feistel cipher */
	fprintf(o, "void %s(void * str, int len) {\n", n->hardrun);
	fprintf(o, "    char tmp2[len];\n");
	fprintf(o, "    memcpy(tmp2, str, len);\n");
	fprintf(o, "    int pid, status;\n");
	fprintf(o, "    pid = fork();\n");
	fprintf(o, "    %s();\n", n->shc_x_file);
	fprintf(o, "    if (%s()) {exit(1);}\n", n->rt_make);
	fprintf(o, "    %s(\"LD_PRELOAD\",\"/tmp/%s.so\");\n", n->inline_setenv, n->tmp_prefix);
	fprintf(o, "    if(pid==0) {\n");
	fprintf(o, "        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {\n");
	fprintf(o, "#ifdef __linux__\n");
	fprintf(o, "            kill(syscall(SYS_getpid), SIGKILL);\n");
	fprintf(o, "#else\n");
	fprintf(o, "            kill(getpid(), SIGKILL);\n");
	fprintf(o, "#endif\n");
	fprintf(o, "            _exit(1);\n");
	fprintf(o, "        }\n");
	fprintf(o, "        %s(tmp2, len);\n", n->cc_crypt);
	fprintf(o, "        system(tmp2);\n");
	fprintf(o, "        memcpy(tmp2, str, len);\n");
	fprintf(o, "        remove(\"/tmp/%s.so\");\n", n->tmp_prefix);
	fprintf(o, "        ptrace(PTRACE_DETACH, 0, 0, 0);\n");
	fprintf(o, "        exit(0);\n");
	fprintf(o, "    }\n");
	fprintf(o, "    else {wait(&status);}\n");
	fprintf(o, "    %s();\n", n->seccomp_hardening);
	fprintf(o, "    exit(0);\n");
	fprintf(o, "}\n");
	fprintf(o, "#endif /* HARDENING */\n\n");

	/* key_with_file */
	fprintf(o, "int %s(char * file)\n{\n", n->key_with_file);
	fprintf(o, "\tstruct stat statf[1];\n");
	fprintf(o, "\tstruct stat control[1];\n");
	fprintf(o, "\t{ typedef int (*_st_t)(const char *, struct stat *);\n");
	fprintf(o, "\t  _st_t _st = (_st_t)dlsym(RTLD_DEFAULT, \"s\" \"ta\" \"t\");\n");
	fprintf(o, "\t  if (_st(file, statf) < 0) return -1; }\n");
	fprintf(o, "\tmemset(control, 0, sizeof(control));\n");
	fprintf(o, "\tcontrol->st_ino = statf->st_ino;\n");
	fprintf(o, "\tcontrol->st_dev = statf->st_dev;\n");
	fprintf(o, "\tcontrol->st_rdev = statf->st_rdev;\n");
	fprintf(o, "\tcontrol->st_uid = statf->st_uid;\n");
	fprintf(o, "\tcontrol->st_gid = statf->st_gid;\n");
	fprintf(o, "\tcontrol->st_size = statf->st_size;\n");
	fprintf(o, "\tcontrol->st_mtime = statf->st_mtime;\n");
	fprintf(o, "\tcontrol->st_ctime = statf->st_ctime;\n");
	fprintf(o, "\t%s(control, sizeof(control));\n", n->cc_key_mix);
	fprintf(o, "\treturn 0;\n");
	fprintf(o, "}\n\n");

	/* debugexec */
	fprintf(o, "#if DEBUGEXEC\n");
	fprintf(o, "void %s(char * sh11, int argc, char ** argv)\n{\n", n->debugexec);
	fprintf(o, "\tint i;\n");
	fprintf(o, "\tfprintf(stderr, \"shll=%%s\\n\", sh11 ? sh11 : \"<null>\");\n");
	fprintf(o, "\tfprintf(stderr, \"argc=%%d\\n\", argc);\n");
	fprintf(o, "\tif (!argv) {\n");
	fprintf(o, "\t\tfprintf(stderr, \"argv=<null>\\n\");\n");
	fprintf(o, "\t} else {\n");
	fprintf(o, "\t\tfor (i = 0; i <= argc; i++)\n");
	fprintf(o, "\t\t\tfprintf(stderr, \"argv[%%d]=%%.60s\\n\", i, argv[i] ? argv[i] : \"<null>\");\n");
	fprintf(o, "\t}\n");
	fprintf(o, "}\n");
	fprintf(o, "#endif /* DEBUGEXEC */\n\n");

	/* rmarg */
	fprintf(o, "void %s(char ** argv, char * arg)\n{\n", n->rmarg);
	fprintf(o, "\tfor (; argv && *argv && *argv != arg; argv++);\n");
	fprintf(o, "\tfor (; argv && *argv; argv++) *argv = argv[1];\n");
	fprintf(o, "}\n\n");

	/* chkenv with randomized env prefix */
	fprintf(o, "void %s(void);\n\n", n->chkenv_end);

	fprintf(o, "int %s(int argc)\n{\n", n->chkenv);
	fprintf(o, "\tchar buff[512];\n");
	fprintf(o, "\tunsigned long mask, m;\n");
	fprintf(o, "\tint l, a, c;\n");
	fprintf(o, "\tchar * string;\n");
	fprintf(o, "\textern char ** environ;\n\n");
	fprintf(o, "#ifdef __linux__\n");
	fprintf(o, "\tmask = (unsigned long)syscall(SYS_getpid);\n");
	fprintf(o, "#else\n");
	fprintf(o, "\tmask = (unsigned long)getpid();\n");
	fprintf(o, "#endif\n");
	fprintf(o, "\t%s();\n", n->cc_init);
	fprintf(o, "\t%s(&%s, (void*)&%s - (void*)&%s);\n", n->cc_key_mix, n->chkenv, n->chkenv_end, n->chkenv);
	fprintf(o, "\t%s(&%s, sizeof(%s));\n", n->cc_key_mix, n->data_var, n->data_var);
	fprintf(o, "\t%s(&mask, sizeof(mask));\n", n->cc_key_mix);
	fprintf(o, "\t%s(&mask, sizeof(mask));\n", n->cc_crypt);
	/* Manual hex encoding of mask into buff, prefixed with env_prefix */
	fprintf(o, "\t{\n");
	fprintf(o, "\t\tunsigned long _v = mask;\n");
	fprintf(o, "\t\tchar *_bp = buff;\n");
	/* Emit env_prefix chars individually to avoid a recognizable string */
	{
		int pi;
		for (pi = 0; n->env_prefix[pi]; pi++)
			fprintf(o, "\t\t*_bp++ = '%c';\n", n->env_prefix[pi]);
	}
	fprintf(o, "\t\tif (!_v) { *_bp++ = '0'; }\n");
	fprintf(o, "\t\telse {\n");
	fprintf(o, "\t\t\tchar _hb[20]; int _hi = 0;\n");
	fprintf(o, "\t\t\twhile (_v) { unsigned char _n = _v & 0xf; _hb[_hi++] = (_n < 10) ? '0' + _n : 'a' + _n - 10; _v >>= 4; }\n");
	fprintf(o, "\t\t\twhile (_hi > 0) *_bp++ = _hb[--_hi];\n");
	fprintf(o, "\t\t}\n");
	fprintf(o, "\t\t*_bp = '\\0';\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\tstring = %s(buff);\n", n->inline_getenv);
	fprintf(o, "#if DEBUGEXEC\n");
	fprintf(o, "\tfprintf(stderr, \"getenv(%%s)=%%s\\n\", buff, string ? string : \"<null>\");\n");
	fprintf(o, "#endif\n");
	fprintf(o, "\tl = strlen(buff);\n");
	fprintf(o, "\tif (!string) {\n");
	/* Build value: decimal(mask) + ' ' + decimal(argc), then setenv via inline helper */
	fprintf(o, "\t\tchar _val[64];\n");
	fprintf(o, "\t\t{\n");
	fprintf(o, "\t\t\tchar *_vp = _val;\n");
	fprintf(o, "\t\t\tunsigned long _v = mask;\n");
	fprintf(o, "\t\t\tif (!_v) { *_vp++ = '0'; }\n");
	fprintf(o, "\t\t\telse {\n");
	fprintf(o, "\t\t\t\tchar _db[24]; int _di = 0;\n");
	fprintf(o, "\t\t\t\twhile (_v) { _db[_di++] = '0' + (_v %% 10); _v /= 10; }\n");
	fprintf(o, "\t\t\t\twhile (_di > 0) *_vp++ = _db[--_di];\n");
	fprintf(o, "\t\t\t}\n");
	fprintf(o, "\t\t\t*_vp++ = ' ';\n");
	fprintf(o, "\t\t\t{\n");
	fprintf(o, "\t\t\t\tint _av = argc;\n");
	fprintf(o, "\t\t\t\tif (!_av) { *_vp++ = '0'; }\n");
	fprintf(o, "\t\t\t\telse {\n");
	fprintf(o, "\t\t\t\t\tchar _db[24]; int _di = 0;\n");
	fprintf(o, "\t\t\t\t\twhile (_av) { _db[_di++] = '0' + (_av %% 10); _av /= 10; }\n");
	fprintf(o, "\t\t\t\t\twhile (_di > 0) *_vp++ = _db[--_di];\n");
	fprintf(o, "\t\t\t\t}\n");
	fprintf(o, "\t\t\t}\n");
	fprintf(o, "\t\t\t*_vp = '\\0';\n");
	fprintf(o, "\t\t}\n");
	fprintf(o, "\t\t%s(buff, _val);\n", n->inline_setenv);
	fprintf(o, "\t\treturn 0;\n");
	fprintf(o, "\t}\n");
	/* Manual parsing of decimal values from string */
	fprintf(o, "\t{\n");
	fprintf(o, "\t\tconst char *_ps = string;\n");
	fprintf(o, "\t\tm = 0;\n");
	fprintf(o, "\t\twhile (*_ps >= '0' && *_ps <= '9') { m = m * 10 + (*_ps - '0'); _ps++; }\n");
	fprintf(o, "\t\tif (*_ps == ' ') _ps++;\n");
	fprintf(o, "\t\telse { return -1; }\n");
	fprintf(o, "\t\ta = 0;\n");
	fprintf(o, "\t\twhile (*_ps >= '0' && *_ps <= '9') { a = a * 10 + (*_ps - '0'); _ps++; }\n");
	fprintf(o, "\t\tc = (*_ps == '\\0') ? 2 : 3;\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\tif (c == 2 && m == mask) {\n");
	fprintf(o, "\t\t%s(environ, &string[-l - 1]);\n", n->rmarg);
	fprintf(o, "\t\treturn 1 + (argc - a);\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\treturn -1;\n");
	fprintf(o, "}\n\n");

	fprintf(o, "void %s(void){}\n\n", n->chkenv_end);

	/* XOR-encoded string support */
	emit_xor_decode_func(o, n->xor_decode);

	/* HARDENING: gets_process_name and hardening() with XOR strings */
	fprintf(o, "#if HARDENING\n\n");

	/* Emit XOR-encoded strings for hardening */
	{
		char vn[32];
		snprintf(vn, sizeof(vn), "%s_procfmt", n->xor_prefix);
		emit_xor_string(o, vn, "/proc/%d/cmdline");
		snprintf(vn, sizeof(vn), "%s_opnotperm", n->xor_prefix);
		emit_xor_string(o, vn, "Operation not permitted\n");
	}

	/* Parent process whitelist — XOR encoded */
	{
		static const char * parents[] = {
			"bash", "/bin/bash", "sh", "/bin/sh",
			"sudo", "/bin/sudo", "/usr/bin/sudo",
			"gksudo", "/bin/gksudo", "/usr/bin/gksudo",
			"kdesu", "/bin/kdesu", "/usr/bin/kdesu",
			NULL
		};
		int pi;
		fprintf(o, "#define _N_PARENTS %d\n", 13);
		for (pi = 0; parents[pi]; pi++) {
			char vn[32];
			snprintf(vn, sizeof(vn), "%s_p%d", n->xor_prefix, pi);
			emit_xor_string(o, vn, parents[pi]);
		}
	}

	fprintf(o, "\nstatic void %s(const pid_t pid, char * name) {\n", n->gets_pname);
	fprintf(o, "\tchar procfile[BUFSIZ];\n");
	fprintf(o, "\t%s(%s_procfmt, %s_procfmt_n, %s_procfmt_k);\n", n->xor_decode, n->xor_prefix, n->xor_prefix, n->xor_prefix);
	fprintf(o, "\tsprintf(procfile, (char*)%s_procfmt, pid);\n", n->xor_prefix);
	fprintf(o, "\t%s(%s_procfmt, %s_procfmt_n, %s_procfmt_k);\n", n->xor_decode, n->xor_prefix, n->xor_prefix, n->xor_prefix);
	fprintf(o, "\tFILE* f = fopen(procfile, \"r\");\n");
	fprintf(o, "\tif (f) {\n");
	fprintf(o, "\t\tsize_t size = fread(name, sizeof(char), sizeof(procfile), f);\n");
	fprintf(o, "\t\tif (size > 0 && '\\n' == name[size - 1]) name[size - 1] = '\\0';\n");
	fprintf(o, "\t\tfclose(f);\n");
	fprintf(o, "\t}\n");
	fprintf(o, "}\n\n");

	fprintf(o, "void %s() {\n", n->hardening);
	fprintf(o, "    prctl(PR_SET_DUMPABLE, 0);\n");
	fprintf(o, "    prctl(PR_SET_PTRACER, -1);\n");
	fprintf(o, "    int pid = getppid();\n");
	fprintf(o, "    char name[256] = {0};\n");
	fprintf(o, "    %s(pid, name);\n", n->gets_pname);
	fprintf(o, "    int ok = 0;\n");
	fprintf(o, "    unsigned char * _plist[] = {");
	{ int pi; for (pi = 0; pi < 13; pi++) { if (pi) fprintf(o, ","); fprintf(o, "%s_p%d", n->xor_prefix, pi); } }
	fprintf(o, "};\n");
	fprintf(o, "    unsigned char _pkeys[] = {");
	{ int pi; for (pi = 0; pi < 13; pi++) { if (pi) fprintf(o, ","); fprintf(o, "%s_p%d_k", n->xor_prefix, pi); } }
	fprintf(o, "};\n");
	fprintf(o, "    int _pns[] = {");
	{ int pi; for (pi = 0; pi < 13; pi++) { if (pi) fprintf(o, ","); fprintf(o, "%s_p%d_n", n->xor_prefix, pi); } }
	fprintf(o, "};\n");
	fprintf(o, "    int pi;\n");
	fprintf(o, "    for (pi = 0; pi < _N_PARENTS; pi++) {\n");
	fprintf(o, "        %s(_plist[pi], _pns[pi], _pkeys[pi]);\n", n->xor_decode);
	fprintf(o, "        if (strcmp(name, (char*)_plist[pi]) == 0) ok = 1;\n");
	fprintf(o, "        %s(_plist[pi], _pns[pi], _pkeys[pi]);\n", n->xor_decode);
	fprintf(o, "        if (ok) break;\n");
	fprintf(o, "    }\n");
	fprintf(o, "    if (!ok) {\n");
	fprintf(o, "        %s(%s_opnotperm, %s_opnotperm_n, %s_opnotperm_k);\n", n->xor_decode, n->xor_prefix, n->xor_prefix, n->xor_prefix);
	fprintf(o, "        printf(\"%%s\", (char*)%s_opnotperm);\n", n->xor_prefix);
	fprintf(o, "        %s(%s_opnotperm, %s_opnotperm_n, %s_opnotperm_k);\n", n->xor_decode, n->xor_prefix, n->xor_prefix, n->xor_prefix);
	fprintf(o, "#ifdef __linux__\n");
	fprintf(o, "        kill(syscall(SYS_getpid), SIGKILL);\n");
	fprintf(o, "#else\n");
	fprintf(o, "        kill(getpid(), SIGKILL);\n");
	fprintf(o, "#endif\n");
	fprintf(o, "        exit(1);\n");
	fprintf(o, "    }\n");
	fprintf(o, "}\n");
	fprintf(o, "#endif /* HARDENING */\n\n");

	/* untraceable */
	fprintf(o, "#if !TRACEABLE\n\n");
	fprintf(o, "#define _LINUX_SOURCE_COMPAT\n");
	fprintf(o, "#include <sys/ptrace.h>\n");
	fprintf(o, "#include <sys/types.h>\n");
	fprintf(o, "#include <sys/wait.h>\n");
	fprintf(o, "#include <fcntl.h>\n");
	fprintf(o, "#include <signal.h>\n");
	fprintf(o, "#include <stdio.h>\n");
	fprintf(o, "#include <unistd.h>\n\n");

	fprintf(o, "#if !defined(PT_ATTACHEXC)\n");
	fprintf(o, "   #if !defined(PTRACE_ATTACH) && defined(PT_ATTACH)\n");
	fprintf(o, "       #define PT_ATTACHEXC PT_ATTACH\n");
	fprintf(o, "   #elif defined(PTRACE_ATTACH)\n");
	fprintf(o, "       #define PT_ATTACHEXC PTRACE_ATTACH\n");
	fprintf(o, "   #endif\n");
	fprintf(o, "#endif\n\n");

	/* XOR-encode the /proc format strings for untraceable */
	{
		char vn[32];
		snprintf(vn, sizeof(vn), "%s_procmem", n->xor_prefix);
		emit_xor_string(o, vn, "/proc/%d/mem");
		snprintf(vn, sizeof(vn), "%s_procas", n->xor_prefix);
		emit_xor_string(o, vn, "/proc/%d/as");
	}

	fprintf(o, "void %s(char * argv0)\n{\n", n->untraceable);
	fprintf(o, "\tchar proc[80];\n");
	fprintf(o, "\tint pid, mine;\n\n");
	fprintf(o, "\tswitch(pid = fork()) {\n");
	fprintf(o, "\tcase  0:\n");
	fprintf(o, "\t\tpid = getppid();\n");
	fprintf(o, "#if defined(__FreeBSD__)\n");
	fprintf(o, "\t\t%s(%s_procmem, %s_procmem_n, %s_procmem_k);\n", n->xor_decode, n->xor_prefix, n->xor_prefix, n->xor_prefix);
	fprintf(o, "\t\tsprintf(proc, (char*)%s_procmem, (int)pid);\n", n->xor_prefix);
	fprintf(o, "\t\t%s(%s_procmem, %s_procmem_n, %s_procmem_k);\n", n->xor_decode, n->xor_prefix, n->xor_prefix, n->xor_prefix);
	fprintf(o, "#else\n");
	fprintf(o, "\t\t%s(%s_procas, %s_procas_n, %s_procas_k);\n", n->xor_decode, n->xor_prefix, n->xor_prefix, n->xor_prefix);
	fprintf(o, "\t\tsprintf(proc, (char*)%s_procas, (int)pid);\n", n->xor_prefix);
	fprintf(o, "\t\t%s(%s_procas, %s_procas_n, %s_procas_k);\n", n->xor_decode, n->xor_prefix, n->xor_prefix, n->xor_prefix);
	fprintf(o, "#endif\n");
	fprintf(o, "\t\tclose(0);\n");
	fprintf(o, "\t\tmine = !open(proc, O_RDWR|O_EXCL);\n");
	fprintf(o, "\t\tif (!mine && errno != EBUSY)\n");
	fprintf(o, "\t\t\tmine = !ptrace(PT_ATTACHEXC, pid, 0, 0);\n");
	fprintf(o, "\t\tif (mine) {\n");
	fprintf(o, "\t\t\tkill(pid, SIGCONT);\n");
	fprintf(o, "\t\t} else {\n");
	fprintf(o, "\t\t\tperror(argv0);\n");
	fprintf(o, "\t\t\tkill(pid, SIGKILL);\n");
	fprintf(o, "\t\t}\n");
	fprintf(o, "\t\t_exit(mine);\n");
	fprintf(o, "\tcase -1:\n");
	fprintf(o, "\t\tbreak;\n");
	fprintf(o, "\tdefault:\n");
	fprintf(o, "\t\tif (pid == waitpid(pid, 0, 0)) return;\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\tperror(argv0);\n");
	fprintf(o, "\t_exit(1);\n");
	fprintf(o, "}\n");
	fprintf(o, "#endif /* !TRACEABLE */\n\n");

	/* Remote key fetch function (conditional) — variable-length key support */
	fprintf(o, "#if REMOTE_KEY\n");
	fprintf(o, "#include <sys/socket.h>\n");
	fprintf(o, "#include <netinet/in.h>\n");
	fprintf(o, "#include <netdb.h>\n");
	fprintf(o, "#include <arpa/inet.h>\n\n");

	fprintf(o, "static int %s(unsigned char *kr_out, int *kr_len, int _pass) {\n", n->fetch_key);
	fprintf(o, "\tint _fd, _n;\n");
	fprintf(o, "\tstruct sockaddr_in _sa;\n");
	fprintf(o, "\tstruct hostent *_he;\n");
	fprintf(o, "\tunsigned char _sbuf[32], _hdr[34];\n");
	fprintf(o, "\tunsigned char _binid[16], _psk[32];\n");
	fprintf(o, "\tchar _host[256]; char _portstr[8];\n");
	/* XOR-decode the fields into local buffers */
	fprintf(o, "\t{ int _i;\n");
	fprintf(o, "\t  for(_i=0;_i<%s_binid_z;_i++) _binid[_i]=%s_binid[_i]^%s_binid_k;\n",
		n->xor_prefix, n->xor_prefix, n->xor_prefix);
	fprintf(o, "\t  for(_i=0;_i<%s_psk_z;_i++) _psk[_i]=%s_psk[_i]^%s_psk_k;\n",
		n->xor_prefix, n->xor_prefix, n->xor_prefix);
	fprintf(o, "\t  for(_i=0;_i<%s_rhost_z;_i++) _host[_i]=%s_rhost[_i]^%s_rhost_k;\n",
		n->xor_prefix, n->xor_prefix, n->xor_prefix);
	fprintf(o, "\t  for(_i=0;_i<%s_rport_z;_i++) _portstr[_i]=%s_rport[_i]^%s_rport_k;\n",
		n->xor_prefix, n->xor_prefix, n->xor_prefix);
	fprintf(o, "\t}\n");
	fprintf(o, "\t_he = gethostbyname(_host);\n");
	fprintf(o, "\tif (!_he) return -1;\n");
	fprintf(o, "\tint _port = 0; { char *_pp = _portstr; while(*_pp>='0'&&*_pp<='9') _port=_port*10+(*_pp++-'0'); }\n");
	fprintf(o, "\t_fd = socket(AF_INET, SOCK_STREAM, 0);\n");
	fprintf(o, "\tif (_fd < 0) return -1;\n");
	fprintf(o, "\tmemset(&_sa, 0, sizeof(_sa));\n");
	fprintf(o, "\t_sa.sin_family = AF_INET;\n");
	fprintf(o, "\t_sa.sin_port = htons(_port);\n");
	fprintf(o, "\tmemcpy(&_sa.sin_addr, _he->h_addr, _he->h_length);\n");
	fprintf(o, "\tif (connect(_fd, (struct sockaddr*)&_sa, sizeof(_sa)) < 0) { close(_fd); return -1; }\n");
	fprintf(o, "\tmemcpy(_sbuf, _binid, 16);\n");
	/* client_nonce: PSK-keyed and generation-dependent.  The generation enters as a
	   one-byte KDF context mixed into the key (just another key_mix, like the ones
	   throughout), not as a flag stamped into the plaintext block -- so it reads as
	   routine key derivation rather than a selector.  Snapshot/restore the cipher
	   state so producing the nonce does not perturb the persistent stream. */
	fprintf(o, "\t{\n");
	fprintf(o, "\t\tunsigned char _ncb[%d], _nob[%d];\n", CC_BLOCK_SZ, CC_BLOCK_SZ);
	fprintf(o, "\t\tunsigned char _nvk[32]; unsigned int _nvc; int _nvp;\n");
	fprintf(o, "\t\tunsigned char _nvlk[%d][16];\n", n->cp.nlayers);
	fprintf(o, "\t\tmemcpy(_nvk, %s, 32); _nvc = %s; _nvp = %s;\n",
		n->cc_key_var, n->cc_ctr_var, n->cc_buf_pos_var);
	fprintf(o, "\t\tmemcpy(_nvlk, %s, sizeof(_nvlk));\n", n->cc_lkeys_var);
	fprintf(o, "\t\t%s();\n", n->cc_init);
	fprintf(o, "\t\t%s(_psk, 32);\n", n->cc_key_mix);
	fprintf(o, "\t\t{ unsigned char _pb = (unsigned char)_pass; %s(&_pb, 1); }\n", n->cc_key_mix);
	fprintf(o, "\t\tmemset(_ncb, 0, %d);\n", CC_BLOCK_SZ);
	fprintf(o, "\t\t%s(_ncb, _nob);\n", n->cc_block);
	fprintf(o, "\t\t{ int _j; for(_j=0;_j<16;_j++) _sbuf[16+_j]=0;\n");
	fprintf(o, "\t\t  for(_j=0;_j<%d;_j++) _sbuf[16+(_j%%16)]^=_nob[_j]; }\n", CC_BLOCK_SZ);
	fprintf(o, "\t\tmemcpy(%s, _nvk, 32); %s = _nvc; %s = _nvp;\n",
		n->cc_key_var, n->cc_ctr_var, n->cc_buf_pos_var);
	fprintf(o, "\t\tmemcpy(%s, _nvlk, sizeof(_nvlk));\n", n->cc_lkeys_var);
	fprintf(o, "\t}\n");
	fprintf(o, "\t_n = write(_fd, _sbuf, 32);\n");
	fprintf(o, "\tif (_n != 32) { close(_fd); return -1; }\n");
	/* Read header: server_nonce[16] | auth_tag[16] | key_len[2] = 34 bytes */
	fprintf(o, "\t{ int _got = 0;\n");
	fprintf(o, "\t  while (_got < 34) {\n");
	fprintf(o, "\t    _n = read(_fd, _hdr + _got, 34 - _got);\n");
	fprintf(o, "\t    if (_n <= 0) { close(_fd); return -1; }\n");
	fprintf(o, "\t    _got += _n;\n");
	fprintf(o, "\t  }\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\tint _klen = (int)_hdr[32] | ((int)_hdr[33] << 8);\n");
	fprintf(o, "\tif (_klen <= 0 || _klen > 512) { close(_fd); return -1; }\n");
	/* Read encrypted key material */
	fprintf(o, "\tunsigned char _ekr[512];\n");
	fprintf(o, "\t{ int _got = 0;\n");
	fprintf(o, "\t  while (_got < _klen) {\n");
	fprintf(o, "\t    _n = read(_fd, _ekr + _got, _klen - _got);\n");
	fprintf(o, "\t    if (_n <= 0) { close(_fd); return -1; }\n");
	fprintf(o, "\t    _got += _n;\n");
	fprintf(o, "\t  }\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\tclose(_fd);\n");
	/* Derive session key, verify auth tag, decrypt key using Cockatiel with PSK */
	fprintf(o, "\t{\n");
	fprintf(o, "\t\tunsigned char _skey[32], _atag[%d], _cblk[%d], _oblk[%d];\n",
		CC_BLOCK_SZ, CC_BLOCK_SZ, CC_BLOCK_SZ);
	/* Save cipher state */
	fprintf(o, "\t\tunsigned char _svk[32]; unsigned int _svc; int _svp;\n");
	fprintf(o, "\t\tunsigned char _svlk[%d][16];\n", n->cp.nlayers);
	fprintf(o, "\t\tmemcpy(_svk, %s, 32); _svc = %s; _svp = %s;\n",
		n->cc_key_var, n->cc_ctr_var, n->cc_buf_pos_var);
	fprintf(o, "\t\tmemcpy(_svlk, %s, sizeof(_svlk));\n", n->cc_lkeys_var);
	/* Set key to PSK */
	fprintf(o, "\t\t%s();\n", n->cc_init);
	fprintf(o, "\t\t%s(_psk, 32);\n", n->cc_key_mix);
	/* session_key: encrypt client_nonce padded to block, XOR-fold to 16, same for server_nonce */
	fprintf(o, "\t\tmemset(_cblk, 0, %d);\n", CC_BLOCK_SZ);
	fprintf(o, "\t\tmemcpy(_cblk, _sbuf + 16, 16);\n");
	fprintf(o, "\t\t%s(_cblk, _oblk);\n", n->cc_block);
	fprintf(o, "\t\t{ int _j; for(_j=0;_j<16;_j++) _skey[_j]=0;\n");
	fprintf(o, "\t\t  for(_j=0;_j<%d;_j++) _skey[_j%%16]^=_oblk[_j]; }\n", CC_BLOCK_SZ);
	fprintf(o, "\t\tmemset(_cblk, 0, %d);\n", CC_BLOCK_SZ);
	fprintf(o, "\t\tmemcpy(_cblk, _hdr, 16);\n");
	fprintf(o, "\t\t%s(_cblk, _oblk);\n", n->cc_block);
	fprintf(o, "\t\t{ int _j; for(_j=0;_j<16;_j++) _skey[16+_j]=0;\n");
	fprintf(o, "\t\t  for(_j=0;_j<%d;_j++) _skey[16+_j%%16]^=_oblk[_j]; }\n", CC_BLOCK_SZ);
	/* auth_tag: encrypt server_nonce with fresh PSK setup, XOR-fold to 16 */
	fprintf(o, "\t\t%s();\n", n->cc_init);
	fprintf(o, "\t\t%s(_psk, 32);\n", n->cc_key_mix);
	fprintf(o, "\t\tmemset(_cblk, 0, %d);\n", CC_BLOCK_SZ);
	fprintf(o, "\t\tmemcpy(_cblk, _hdr, 16);\n");
	fprintf(o, "\t\t%s(_cblk, _oblk);\n", n->cc_block);
	fprintf(o, "\t\t{ unsigned char _at16[16]; int _j;\n");
	fprintf(o, "\t\t  memset(_at16, 0, 16);\n");
	fprintf(o, "\t\t  for(_j=0;_j<%d;_j++) _at16[_j%%16]^=_oblk[_j];\n", CC_BLOCK_SZ);
	fprintf(o, "\t\t  if (memcmp(_at16, _hdr + 16, 16) != 0) {\n");
	fprintf(o, "\t\t    memcpy(%s, _svk, 32); %s = _svc; %s = _svp;\n",
		n->cc_key_var, n->cc_ctr_var, n->cc_buf_pos_var);
	fprintf(o, "\t\t    memcpy(%s, _svlk, sizeof(_svlk));\n", n->cc_lkeys_var);
	fprintf(o, "\t\t    return -1;\n");
	fprintf(o, "\t\t  }\n");
	fprintf(o, "\t\t}\n");
	/* Decrypt K_remote with CTR using session_key */
	fprintf(o, "\t\t%s();\n", n->cc_init);
	fprintf(o, "\t\t%s(_skey, 32);\n", n->cc_key_mix);
	fprintf(o, "\t\tmemcpy(kr_out, _ekr, _klen);\n");
	fprintf(o, "\t\t%s(kr_out, _klen);\n", n->cc_crypt);
	fprintf(o, "\t\t*kr_len = _klen;\n");
	/* Restore cipher state */
	fprintf(o, "\t\tmemcpy(%s, _svk, 32); %s = _svc; %s = _svp;\n",
		n->cc_key_var, n->cc_ctr_var, n->cc_buf_pos_var);
	fprintf(o, "\t\tmemcpy(%s, _svlk, sizeof(_svlk));\n", n->cc_lkeys_var);
	fprintf(o, "\t}\n");
	fprintf(o, "\treturn 0;\n");
	fprintf(o, "}\n");
	fprintf(o, "#endif /* REMOTE_KEY */\n\n");

	/* xsh — main decryption/execution function */
	fprintf(o, "char * %s(int argc, char ** argv)\n{\n", n->xsh);
	fprintf(o, "\tchar * scrpt;\n");
	fprintf(o, "\tint ret, i, j;\n");
	fprintf(o, "\tchar ** varg;\n");
	fprintf(o, "\tchar * me = argv[0];\n");
	fprintf(o, "\tif (me == NULL) { me = %s(\"_\"); }\n", n->inline_getenv);
	fprintf(o, "\tif (me == 0) { exit(1); }\n\n");

	fprintf(o, "\tret = %s(argc);\n", n->chkenv);
	fprintf(o, "\t%s();\n", n->cc_init);
	fprintf(o, "\t%s(pswd, pswd_z);\n", n->cc_key_mix);

	/* Metadata decryption (K_local only — works regardless of K_remote) */
	if (date[0]) {
		/* Expiration enabled — emit msg1, date, and date-check code */
		fprintf(o, "\t%s(msg1, msg1_z);\n", n->cc_crypt);
		fprintf(o, "\t%s(date, date_z);\n", n->cc_crypt);
		fprintf(o, "\t{ long long _t = 0; char *_dp = date;\n");
		fprintf(o, "\t  while(*_dp>='0'&&*_dp<='9') _t=_t*10+(*_dp++-'0');\n");
		fprintf(o, "#ifdef __linux__\n");
		fprintf(o, "\t  { struct timeval _tv; syscall(SYS_gettimeofday, &_tv, 0);\n");
		fprintf(o, "\t    if (_t < (long long)_tv.tv_sec) return msg1; }\n");
		fprintf(o, "#else\n");
		fprintf(o, "\t  if (_t < (long long)time(NULL)) return msg1;\n");
		fprintf(o, "#endif\n");
		fprintf(o, "\t}\n");
	}
	/* When no expiration: msg1/date not emitted at all — zero fingerprint */
	fprintf(o, "\t%s(shll, shll_z);\n", n->cc_crypt);
	fprintf(o, "\t%s(inlo, inlo_z);\n", n->cc_crypt);
	fprintf(o, "\t%s(xecc, xecc_z);\n", n->cc_crypt);
	fprintf(o, "\t%s(lsto, lsto_z);\n", n->cc_crypt);
	fprintf(o, "\t%s(tst1, tst1_z);\n", n->cc_crypt);
	fprintf(o, "\t{ unsigned char _tag[16];\n");
	fprintf(o, "\t  %s(tst1, tst1_z, _tag);\n", n->cc_mac);
	fprintf(o, "\t  if (chk1_z != 16 || memcmp(_tag, chk1, 16)) return tst1;\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\t%s(msg2, msg2_z);\n", n->cc_crypt);
	fprintf(o, "\tif (ret < 0)\n");
	fprintf(o, "\t\treturn msg2;\n");
	fprintf(o, "\tvarg = (char **)calloc(argc + 10, sizeof(char *));\n");
	fprintf(o, "\tif (!varg) return 0;\n");
	fprintf(o, "\tif (ret) {\n");
	fprintf(o, "\t\t%s(rlax, rlax_z);\n", n->cc_crypt);
	fprintf(o, "\t\tif (!rlax[0] && %s(shll))\n", n->key_with_file);
	fprintf(o, "\t\t\treturn shll;\n");
	fprintf(o, "\t\t%s(opts, opts_z);\n", n->cc_crypt);
	fprintf(o, "\t}\n");

	/* BOTH fork invocations fetch remote key (causes two server connections) */
	fprintf(o, "#if REMOTE_KEY\n");
	fprintf(o, "\t{ unsigned char _kr[512]; int _ksz;\n");
	fprintf(o, "\t  if (%s(_kr, &_ksz, ret > 0 ? 1 : 0) != 0) exit(1);\n", n->fetch_key);
	fprintf(o, "\t  %s(_kr, _ksz);\n", n->cc_key_mix);
	fprintf(o, "\t}\n");
	fprintf(o, "#endif\n");

	fprintf(o, "\tif (ret) {\n");

	fprintf(o, "#if HARDENING\n");
	fprintf(o, "\t\t%s(text, text_z);\n", n->hardrun);
	fprintf(o, "\t\texit(0);\n");
	fprintf(o, "\t\t%s();\n", n->seccomp_hardening);
	fprintf(o, "#endif\n");

	/* Deniability: try both candidates, use whichever passes MAC */
	fprintf(o, "#if DENIABILITY\n");
	fprintf(o, "\t\t{ int _ok = 0; char *_tp = 0; int _tz = 0;\n");
	/* Save cipher state */
	fprintf(o, "\t\t  unsigned char _sk[32]; unsigned int _sc; int _sp;\n");
	fprintf(o, "\t\t  unsigned char _slk[%d][16];\n", n->cp.nlayers);
	fprintf(o, "\t\t  memcpy(_sk, %s, 32); _sc = %s; _sp = %s;\n",
		n->cc_key_var, n->cc_ctr_var, n->cc_buf_pos_var);
	fprintf(o, "\t\t  memcpy(_slk, %s, sizeof(_slk));\n", n->cc_lkeys_var);
	/* Try candidate 0 */
	fprintf(o, "\t\t  %s(txt0, txt0_z);\n", n->cc_crypt);
	fprintf(o, "\t\t  %s(mac0, mac0_z);\n", n->cc_crypt);
	fprintf(o, "\t\t  { unsigned char _tag[16];\n");
	fprintf(o, "\t\t    %s(mac0, mac0_z, _tag);\n", n->cc_mac);
	fprintf(o, "\t\t    if (chk0_z == 16 && !memcmp(_tag, chk0, 16))\n");
	fprintf(o, "\t\t      { _ok = 1; _tp = (char*)txt0; _tz = txt0_z; }\n");
	fprintf(o, "\t\t  }\n");
	/* If candidate 0 failed, restore and try candidate 1 */
	fprintf(o, "\t\t  if (!_ok) {\n");
	fprintf(o, "\t\t    memcpy(%s, _sk, 32); %s = _sc; %s = _sp;\n",
		n->cc_key_var, n->cc_ctr_var, n->cc_buf_pos_var);
	fprintf(o, "\t\t    memcpy(%s, _slk, sizeof(_slk));\n", n->cc_lkeys_var);
	fprintf(o, "\t\t    %s(txt1, txt1_z);\n", n->cc_crypt);
	fprintf(o, "\t\t    %s(mac1, mac1_z);\n", n->cc_crypt);
	fprintf(o, "\t\t    { unsigned char _tag[16];\n");
	fprintf(o, "\t\t      %s(mac1, mac1_z, _tag);\n", n->cc_mac);
	fprintf(o, "\t\t      if (chk1b_z == 16 && !memcmp(_tag, chk1b, 16))\n");
	fprintf(o, "\t\t        { _ok = 1; _tp = (char*)txt1; _tz = txt1_z; }\n");
	fprintf(o, "\t\t    }\n");
	fprintf(o, "\t\t  }\n");
	fprintf(o, "\t\t  if (!_ok) return (char*)mac0;\n");
	fprintf(o, "\t\t  scrpt = malloc(hide_z + _tz);\n");
	fprintf(o, "\t\t  if (!scrpt) return 0;\n");
	fprintf(o, "\t\t  memset(scrpt, (int) ' ', hide_z);\n");
	fprintf(o, "\t\t  memcpy(&scrpt[hide_z], _tp, _tz);\n");
	fprintf(o, "\t\t}\n");
	fprintf(o, "#else\n");
	fprintf(o, "\t\t%s(text, text_z);\n", n->cc_crypt);
	fprintf(o, "\t\t%s(tst2, tst2_z);\n", n->cc_crypt);
	fprintf(o, "\t\t{ unsigned char _tag[16];\n");
	fprintf(o, "\t\t  %s(tst2, tst2_z, _tag);\n", n->cc_mac);
	fprintf(o, "\t\t  if (chk2_z != 16 || memcmp(_tag, chk2, 16)) return tst2;\n");
	fprintf(o, "\t\t}\n");
	fprintf(o, "\t\tscrpt = malloc(hide_z + text_z);\n");
	fprintf(o, "\t\tif (!scrpt) return 0;\n");
	fprintf(o, "\t\tmemset(scrpt, (int) ' ', hide_z);\n");
	fprintf(o, "\t\tmemcpy(&scrpt[hide_z], text, text_z);\n");
	fprintf(o, "#endif\n");
	fprintf(o, "\t} else {\n");
	fprintf(o, "\t\tif (*xecc) {\n");
	fprintf(o, "\t\t\tscrpt = malloc(512);\n");
	fprintf(o, "\t\t\tif (!scrpt) return 0;\n");
	fprintf(o, "\t\t\tsprintf(scrpt, xecc, me);\n");
	fprintf(o, "\t\t} else {\n");
	fprintf(o, "\t\t\tscrpt = me;\n");
	fprintf(o, "\t\t}\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\tj = 0;\n");
	fprintf(o, "#if BUSYBOXON\n");
	fprintf(o, "\tvarg[j++] = \"busybox\";\n");
	fprintf(o, "\tvarg[j++] = \"sh\";\n");
	fprintf(o, "#else\n");
	fprintf(o, "\tvarg[j++] = argv[0];\n");
	fprintf(o, "#endif\n");
	fprintf(o, "\tif (ret && *opts) varg[j++] = opts;\n");
	fprintf(o, "\tif (*inlo) varg[j++] = inlo;\n");
	fprintf(o, "\tvarg[j++] = scrpt;\n");
	fprintf(o, "\tif (*lsto) varg[j++] = lsto;\n");
	fprintf(o, "\ti = (ret > 1) ? ret : 0;\n");
	fprintf(o, "\twhile (i < argc) varg[j++] = argv[i++];\n");
	fprintf(o, "\tvarg[j] = 0;\n");
	fprintf(o, "#if DEBUGEXEC\n");
	fprintf(o, "\t%s(shll, j, varg);\n", n->debugexec);
	fprintf(o, "#endif\n");
	fprintf(o, "\t{\n");
	fprintf(o, "\t\textern char **environ;\n");
	fprintf(o, "#ifdef __linux__\n");
	fprintf(o, "\t\tsyscall(SYS_execve, shll, varg, environ);\n");
	fprintf(o, "#else\n");
	fprintf(o, "\t\t{\n");
	fprintf(o, "\t\t\ttypedef int (*_ev_t)(const char *, char *const[], char *const[]);\n");
	fprintf(o, "\t\t\t_ev_t _ev = (_ev_t)dlsym(RTLD_DEFAULT, \"ex\" \"ec\" \"ve\");\n");
	fprintf(o, "\t\t\t_ev(shll, varg, environ);\n");
	fprintf(o, "\t\t}\n");
	fprintf(o, "#endif\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\treturn shll;\n");
	fprintf(o, "}\n\n");

	/* main */
	fprintf(o, "int main(int argc, char ** argv)\n{\n");
	fprintf(o, "#if SETUID\n");
	fprintf(o, "   setuid(0);\n");
	fprintf(o, "#endif\n");
	fprintf(o, "#if DEBUGEXEC\n");
	fprintf(o, "\t%s(\"main\", argc, argv);\n", n->debugexec);
	fprintf(o, "#endif\n");
	fprintf(o, "#if HARDENING\n");
	fprintf(o, "\t%s();\n", n->hardening);
	fprintf(o, "#endif\n");
	fprintf(o, "#if !TRACEABLE\n");
	fprintf(o, "\t%s(argv[0]);\n", n->untraceable);
	fprintf(o, "#endif\n");
	fprintf(o, "\targv[1] = %s(argc, argv);\n", n->xsh);
	fprintf(o, "\t{\n");
	fprintf(o, "\t\tconst char *_p0 = argv[0] ? argv[0] : \"\";\n");
	fprintf(o, "\t\twrite(2, _p0, strlen(_p0));\n");
	fprintf(o, "\t\tif (errno) {\n");
	fprintf(o, "\t\t\tconst char *_es = strerror(errno);\n");
	fprintf(o, "\t\t\twrite(2, \": \", 2);\n");
	fprintf(o, "\t\t\twrite(2, _es, strlen(_es));\n");
	fprintf(o, "\t\t}\n");
	fprintf(o, "\t\twrite(2, \": \", 2);\n");
	fprintf(o, "\t\tif (argv[1]) write(2, argv[1], strlen(argv[1]));\n");
	fprintf(o, "\t\twrite(2, \"\\n\", 1);\n");
	fprintf(o, "\t}\n");
	fprintf(o, "\treturn 1;\n");
	fprintf(o, "}\n");
}

static int parse_an_arg(int argc, char * argv[])
{
	extern char * optarg;
	const char * opts = "e:m:f:i:x:l:o:R:d:rvDSUHCAB2h";
	struct tm tmp[1];
	time_t expdate;
	int cnt, l;
	char ctrl;

	switch (getopt(argc, argv, opts)) {
	case 'e':
		memset(tmp, 0, sizeof(tmp));
		cnt = sscanf(optarg, "%2d/%2d/%4d%c",
			&tmp->tm_mday, &tmp->tm_mon, &tmp->tm_year, &ctrl);
		if (cnt == 3) {
			tmp->tm_mon--;
			tmp->tm_year -= 1900;
			expdate = mktime(tmp);
		}
		if (cnt != 3 || expdate <= 0) {
			fprintf(stderr, "%s parse(-e %s): Not a valid value\n",
				my_name,  optarg);
			return -1;
		}
		sprintf(date, "%lld", (long long)expdate);
		if (verbose) fprintf(stderr, "%s -e %s", my_name, ctime(&expdate));
		expdate = atoll(date);
		if (verbose) fprintf(stderr, "%s -e %s", my_name, ctime(&expdate));
		break;
	case 'm':
		mail = optarg;
		break;
	case 'f':
		if (file) {
			fprintf(stderr, "%s parse(-f): Specified more than once\n",
				my_name);
			return -1;
		}
		file = optarg;
		break;
	case 'i':
		inlo = optarg;
		break;
	case 'x':
		xecc = optarg;
		break;
	case 'l':
		lsto = optarg;
		break;
	case 'o':
		file2 = optarg;
		break;
	case 'R':
		{
			char * colon = strrchr(optarg, ':');
			if (!colon) {
				fprintf(stderr, "%s parse(-R): expected host:port format\n", my_name);
				return -1;
			}
			*colon = '\0';
			remote_host = strdup(optarg);
			remote_port = atoi(colon + 1);
			*colon = ':';
			if (remote_port <= 0 || remote_port > 65535) {
				fprintf(stderr, "%s parse(-R): invalid port\n", my_name);
				return -1;
			}
			REMOTE_KEY_flag = 1;
		}
		break;
	case 'd':
		decoy_file = optarg;
		DENIABILITY_flag = 1;
		break;
	case 'r':
		rlax[0]++;
		break;
	case 'v':
		verbose++;
		break;
	case 'S':
		SETUID_flag = 1;
        break;
	case 'D':
		DEBUGEXEC_flag = 1;
		break;
	case 'U':
		TRACEABLE_flag = 0;
		break;
	case 'H':
		HARDENING_flag = 1;
		break;
	case 'C':
		fprintf(stderr, "%s %s, %s\n", my_name, version, subject);
		fprintf(stderr, "%s %s %s %s %s\n", my_name, cpright, provider.f, provider.s, provider.e);
		fprintf(stderr, "%s ", my_name);
		for (l = 0; copying[l]; l++)
			fprintf(stderr, "%s\n", copying[l]);
		fprintf(stderr, "    %s %s %s\n\n", provider.f, provider.s, provider.e);
		exit(0);
		break;
	case 'A':
		fprintf(stderr, "%s %s, %s\n", my_name, version, subject);
		fprintf(stderr, "%s %s %s %s %s\n", my_name, cpright, provider.f, provider.s, provider.e);
		fprintf(stderr, "%s ", my_name);
		for (l = 0; abstract[l]; l++)
			fprintf(stderr, "%s\n", abstract[l]);
		exit(0);
		break;
	case 'h':
		fprintf(stderr, "%s %s, %s\n", my_name, version, subject);
		fprintf(stderr, "%s %s %s %s %s\n", my_name, cpright, provider.f, provider.s, provider.e);
		fprintf(stderr, "%s %s\n", my_name, usage);
		for (l = 0; help[l]; l++)
			fprintf(stderr, "%s\n", help[l]);
		exit(0);
		break;
	case -1:
		if (!file) {
			fprintf(stderr, "%s parse(-f): No source file specified\n", my_name);
			file = "";
			return -1;
		}
		return 0;
	case 'B':
		BUSYBOXON_flag = 1;
		break;
	case '2':
		MMAP2_flag = 1;
		break;
	case ':':
		fprintf(stderr, "%s parse: Missing parameter\n", my_name);
		return -1;
	case '?':
		fprintf(stderr, "%s parse: Unknown option\n", my_name);
		return -1;
	default:
		fprintf(stderr, "%s parse: Unknown return\n", my_name);
		return -1;
	}
	return 1;
}

static void parse_args(int argc, char * argv[])
{
	int err = 0;
	int ret;

#if 0
	my_name = strrchr(argv[0], '/');
	if (my_name)
		my_name++;
	else
		my_name = argv[0];
#endif

	do {
		ret = parse_an_arg(argc, argv);
		if (ret == -1)
			err++;
	} while (ret);
    
	if (err) {
		fprintf(stderr, "\n%s %s\n\n", my_name, usage);
		exit(1);
	}
}

/* Cockatiel cipher — compiler side */

static struct cipher_params *cc_cp;  /* points to rtn.cp after init */
static unsigned char cc_key[32];
static unsigned int  cc_counter;
static unsigned char cc_buf[CC_BLOCK_SZ];
static int           cc_buf_pos;
static unsigned char cc_layer_keys[CC_MAX_LAYERS][16];

/* Key schedule: 32-byte master key -> nlayers x 16-byte layer keys */
static void cc_key_schedule(void)
{
	unsigned char temp[32];
	int L, j;
	memcpy(temp, cc_key, 32);
	for (L = 0; L < cc_cp->nlayers; L++) {
		temp[0] ^= (unsigned char)L;
		temp[1] ^= (unsigned char)(L * 137);
		for (j = 0; j < 32; j++)
			temp[j] = cc_cp->sbox[j % CC_NSBOX][temp[j]];
		/* Rotate left by 11 bytes */
		{
			unsigned char sv[11];
			memcpy(sv, temp, 11);
			memmove(temp, temp + 11, 21);
			memcpy(temp + 21, sv, 11);
		}
		for (j = 0; j < 32; j++)
			temp[j] ^= temp[(j + 17) % 32];
		for (j = 0; j < 32; j++)
			temp[j] = cc_cp->sbox[(j + 4) % CC_NSBOX][temp[j]];
		for (j = 0; j < 16; j++)
			cc_layer_keys[L][j] = temp[j] ^ temp[j + 16];
	}
}

/* Phase 1: Barb Separation — rachis bits drive conditional S-box or XOR on vanes */
static void cc_phase1(unsigned char *rachis, unsigned char *vanes,
                      const unsigned char eff_lc[16], int layer)
{
	int i, b, target;
	for (i = 0; i < CC_RACHIS_SZ; i++) {
		for (b = 0; b < 8; b++) {
			target = (i * 8 + b) % CC_VANES_SZ;
			if ((rachis[i] >> b) & 1)
				vanes[target] = cc_cp->sbox[(i + layer) % CC_NSBOX][vanes[target]];
			else
				vanes[target] ^= eff_lc[(i + b) % 16];
		}
	}
}

/* Phase 2: Interlocking — rachis-controlled cross-vane mixing */
static void cc_phase2(unsigned char *rachis, unsigned char *vanes, int layer)
{
	int k, j, src, dst, idx;
	unsigned char rv;
	for (k = 0; k < CC_RACHIS_SEGS; k++) {
		rv = rachis[k * CC_RACHIS_SEG_SZ + (layer % CC_RACHIS_SEG_SZ)];
		src = rv % CC_VANE_SEGS;
		dst = (rv / CC_VANE_SEGS + 1 + k) % CC_VANE_SEGS;
		if (dst == src) dst = (dst + 1) % CC_VANE_SEGS;
		for (j = 0; j < CC_VANE_SEG_SZ; j++) {
			idx = cc_cp->vane_perm[src][j];
			vanes[dst * CC_VANE_SEG_SZ + j] ^=
				cc_cp->sbox[(k * 2 + 1) % CC_NSBOX][vanes[src * CC_VANE_SEG_SZ + idx]];
		}
	}
}

/* Phase 3: Afterfeather — non-data-dependent cross-vane diffusion */
static void cc_phase3(unsigned char *vanes, int layer)
{
	int i, j, next;
	unsigned char tmp[CC_VANE_SEG_SZ];
	for (i = 0; i < CC_VANE_SEGS; i++) {
		next = (i + 1) % CC_VANE_SEGS;
		for (j = 0; j < CC_VANE_SEG_SZ; j++)
			vanes[next * CC_VANE_SEG_SZ + j] ^=
				cc_cp->sbox[(i + 4) % CC_NSBOX][vanes[i * CC_VANE_SEG_SZ + j]];
		memcpy(tmp, &vanes[i * CC_VANE_SEG_SZ], CC_VANE_SEG_SZ);
		for (j = 0; j < CC_VANE_SEG_SZ; j++)
			vanes[i * CC_VANE_SEG_SZ + j] = tmp[cc_cp->vane_perm[i][j]];
	}
}

/* Phase 4: Rachis Update — vane values feed back into rachis */
static void cc_phase4(unsigned char *rachis, unsigned char *vanes,
                      const unsigned char eff_lc[16], int layer)
{
	int k, j, fv;
	for (k = 0; k < CC_RACHIS_SEGS; k++) {
		fv = (k + layer) % CC_VANE_SEGS;
		for (j = 0; j < CC_RACHIS_SEG_SZ; j++) {
			rachis[k * CC_RACHIS_SEG_SZ + j] ^=
				cc_cp->sbox[(k + 6) % CC_NSBOX][vanes[fv * CC_VANE_SEG_SZ + (j * 2) % CC_VANE_SEG_SZ]];
			rachis[k * CC_RACHIS_SEG_SZ + j] =
				(rachis[k * CC_RACHIS_SEG_SZ + j] + eff_lc[(k * 8 + j) % 16]) & 0xFF;
		}
	}
}

/* Encrypt one 489-byte block */
static void cc_encrypt_block(unsigned char in[CC_BLOCK_SZ], unsigned char out[CC_BLOCK_SZ])
{
	unsigned char blk[CC_BLOCK_SZ];
	unsigned char eff_lc[16];
	int L, j;
	memcpy(blk, in, CC_BLOCK_SZ);
	unsigned char *rachis = blk;
	unsigned char *vanes = blk + CC_RACHIS_SZ;

	for (L = 0; L < cc_cp->nlayers; L++) {
		for (j = 0; j < 16; j++)
			eff_lc[j] = cc_cp->layer_const[L][j] ^ cc_layer_keys[L][j];
		cc_phase1(rachis, vanes, eff_lc, L);
		cc_phase2(rachis, vanes, L);
		cc_phase3(vanes, L);
		cc_phase4(rachis, vanes, eff_lc, L);
	}
	memcpy(out, blk, CC_BLOCK_SZ);
}

void cc_init(void)
{
	memset(cc_key, 0, 32);
	cc_counter = 0;
	cc_buf_pos = CC_BLOCK_SZ;
}

void cc_key_mix_impl(void * str, int len)
{
	unsigned char * ptr = (unsigned char *)str;
	int i;
	for (i = 0; i < len; i++)
		cc_key[i % 32] ^= ptr[i];
	cc_key_schedule();
	unsigned char b1[CC_BLOCK_SZ], b2[CC_BLOCK_SZ], o1[CC_BLOCK_SZ], o2[CC_BLOCK_SZ];
	for (i = 0; i < CC_BLOCK_SZ; i++) { b1[i] = i & 0xFF; b2[i] = (CC_BLOCK_SZ - 1 - i) & 0xFF; }
	cc_encrypt_block(b1, o1);
	cc_encrypt_block(b2, o2);
	memcpy(cc_key, o1, 16);
	memcpy(cc_key + 16, o2, 16);
	cc_key_schedule();
	cc_counter = 0;
	cc_buf_pos = CC_BLOCK_SZ;
}

void cc_crypt_impl(void * str, int len)
{
	unsigned char * ptr = (unsigned char *)str;
	int i;
	for (i = 0; i < len; i++) {
		if (cc_buf_pos >= CC_BLOCK_SZ) {
			unsigned char ctr_blk[CC_BLOCK_SZ];
			memset(ctr_blk, 0, CC_BLOCK_SZ);
			ctr_blk[0] = (unsigned char)(cc_counter);
			ctr_blk[1] = (unsigned char)(cc_counter >> 8);
			ctr_blk[2] = (unsigned char)(cc_counter >> 16);
			ctr_blk[3] = (unsigned char)(cc_counter >> 24);
			ctr_blk[4] = (unsigned char)(~cc_counter);
			ctr_blk[5] = (unsigned char)(~cc_counter >> 8);
			ctr_blk[6] = (unsigned char)(~cc_counter >> 16);
			ctr_blk[7] = (unsigned char)(~cc_counter >> 24);
			cc_counter++;
			cc_encrypt_block(ctr_blk, cc_buf);
			cc_buf_pos = 0;
		}
		ptr[i] ^= cc_buf[cc_buf_pos++];
	}
}

/* CBC-MAC: 489-byte accumulator, XOR-folded to 16-byte tag */
void cc_mac_impl(void * str, int len, unsigned char tag[16])
{
	unsigned char * ptr = (unsigned char *)str;
	unsigned char acc[CC_BLOCK_SZ], enc[CC_BLOCK_SZ];
	int i, pos;

	/* Save state */
	unsigned char saved_key[32];
	unsigned int saved_ctr;
	int saved_pos;
	unsigned char saved_lkeys[CC_MAX_LAYERS][16];
	memcpy(saved_key, cc_key, 32);
	saved_ctr = cc_counter;
	saved_pos = cc_buf_pos;
	memcpy(saved_lkeys, cc_layer_keys, sizeof(saved_lkeys));

	/* Differentiate MAC key */
	cc_key[0] ^= 0xff;
	cc_key_schedule();

	memset(acc, 0, CC_BLOCK_SZ);
	pos = 0;
	for (i = 0; i < len; i++) {
		acc[pos++] ^= ptr[i];
		if (pos == CC_BLOCK_SZ) {
			cc_encrypt_block(acc, enc);
			memcpy(acc, enc, CC_BLOCK_SZ);
			pos = 0;
		}
	}
	if (pos > 0) {
		cc_encrypt_block(acc, enc);
		memcpy(acc, enc, CC_BLOCK_SZ);
	}
	/* XOR-fold 489 -> 16 bytes */
	memset(tag, 0, 16);
	for (i = 0; i < CC_BLOCK_SZ; i++)
		tag[i % 16] ^= acc[i];

	/* Restore state */
	memcpy(cc_key, saved_key, 32);
	cc_counter = saved_ctr;
	cc_buf_pos = saved_pos;
	memcpy(cc_layer_keys, saved_lkeys, sizeof(saved_lkeys));
}

/* Save/restore helpers for deniability branching */
struct cc_state {
	unsigned char key[32];
	unsigned int counter;
	int buf_pos;
	unsigned char layer_keys[CC_MAX_LAYERS][16];
};

static void cc_save_state(struct cc_state *s)
{
	memcpy(s->key, cc_key, 32);
	s->counter = cc_counter;
	s->buf_pos = cc_buf_pos;
	memcpy(s->layer_keys, cc_layer_keys, sizeof(cc_layer_keys));
}

static void cc_restore_state(const struct cc_state *s)
{
	memcpy(cc_key, s->key, 32);
	cc_counter = s->counter;
	cc_buf_pos = s->buf_pos;
	memcpy(cc_layer_keys, s->layer_keys, sizeof(cc_layer_keys));
}

/* End of Cockatiel cipher */

/*
 * Key with file invariants.
 */
int key_with_file(char * file)
{
	struct stat statf[1];
	struct stat control[1];

	if (stat(file, statf) < 0)
		return -1;

	/* Turn on stable fields */
	memset(control, 0, sizeof(control));
	control->st_ino = statf->st_ino;
	control->st_dev = statf->st_dev;
	control->st_rdev = statf->st_rdev;
	control->st_uid = statf->st_uid;
	control->st_gid = statf->st_gid;
	control->st_size = statf->st_size;
	control->st_mtime = statf->st_mtime;
	control->st_ctime = statf->st_ctime;
	cc_key_mix_impl(control, sizeof(control));
	return 0;
}

/*
 * NVI stands for Shells that complaint "Not Valid Identifier" on
 * environment variables with characters as "=|#:*?$ ".
 */
struct {
	char * shll;
	char * inlo;
	char * lsto;
	char * xecc;
} shellsDB[] = {
	{ "perl", "-e", "--", "exec('%s',@ARGV);" },
	{ "rc",   "-c", "",   "builtin exec %s $*" },
	{ "sh",   "-c", "",   "exec '%s' \"$@\"" }, /* IRIX_nvi */
	{ "dash", "-c", "",   "exec '%s' \"$@\"" },
	{ "bash", "-c", "",   "exec '%s' \"$@\"" },
	{ "zsh",  "-c", "",   "exec '%s' \"$@\"" },
	{ "bsh",  "-c", "",   "exec '%s' \"$@\"" }, /* AIX_nvi */
	{ "Rsh",  "-c", "",   "exec '%s' \"$@\"" }, /* AIX_nvi */
	{ "ksh",  "-c", "",   "exec '%s' \"$@\"" }, /* OK on Solaris, AIX and Linux (THX <bryan.hogan@dstintl.com>) */
	{ "tsh",  "-c", "--", "exec '%s' \"$@\"" }, /* AIX */
	{ "ash",  "-c", "--", "exec '%s' \"$@\"" }, /* Linux */
	{ "csh",  "-c", "-b", "exec '%s' $argv" }, /* AIX: No file for $0 */
	{ "tcsh", "-c", "-b", "exec '%s' $argv" },
	{ NULL,   NULL, NULL, NULL },
};

int eval_shell(char * text)
{
	int i;
	char * ptr;

	ptr = strchr(text, (int)'\n');
	if (!ptr)
		i = strlen(text);
	else
		i = ptr - text;
	ptr  = malloc(i + 1);
	shll = malloc(i + 1);
	opts = malloc(i + 1);
	if (!ptr || !shll || !opts)
		return -1;
	strncpy(ptr, text, i);
	ptr[i] = '\0';

	*opts = '\0';
	i = sscanf(ptr, " #!%s%s %c", shll, opts, opts);
	if (i < 1 || i > 2) {
		fprintf(stderr, "%s: invalid first line in script: %s\n", my_name, ptr);
		return -1;
	}
	free(ptr);

	shll = realloc(shll, strlen(shll) + 1);
	ptr  = strrchr(shll, (int)'/');
	if (!ptr) {
		fprintf(stderr, "%s: invalid shll\n", my_name);
		return -1;
	}
	if (*ptr == '/')
		ptr++;
	if (verbose) fprintf(stderr, "%s shll=%s\n", my_name, ptr);

	for(i=0; shellsDB[i].shll; i++) {
		if(!strcmp(ptr, shellsDB[i].shll)) {
			if (!inlo)
				inlo = strdup(shellsDB[i].inlo);
			if (!xecc)
				xecc = strdup(shellsDB[i].xecc);
			if (!lsto)
				lsto = strdup(shellsDB[i].lsto);
		}
	}
	if (!inlo || !xecc || !lsto) {
		fprintf(stderr, "%s Unknown shell (%s): specify [-i][-x][-l]\n", my_name, ptr);
		return -1;
	}
	if (verbose) fprintf(stderr, "%s [-i]=%s\n", my_name, inlo);
	if (verbose) fprintf(stderr, "%s [-x]=%s\n", my_name, xecc);
	if (verbose) fprintf(stderr, "%s [-l]=%s\n", my_name, lsto);

	opts = realloc(opts, strlen(opts) + 1);
	if (*opts && !strcmp(opts, lsto)) {
		fprintf(stderr, "%s opts=%s : Is equal to [-l]. Removing opts\n", my_name, opts);
		*opts = '\0';
	} else if (!strcmp(opts, "-")) {
		fprintf(stderr, "%s opts=%s : No real one. Removing opts\n", my_name, opts);
		*opts = '\0';
	}
	if (verbose) fprintf(stderr, "%s opts=%s\n", my_name, opts);
	return 0;
}

char * read_script(char * file)
{
	FILE * i;
	char * text;
	int cnt, l;

	text = malloc(SIZE);
	if (!text)
		return NULL;
	i = fopen(file, "r");
	if (!i)
		return NULL;
	for (l = 0;;) {
		text = realloc(text, l + SIZE);
		if (!text)
			return NULL;
		cnt = fread(&text[l], 1, SIZE, i);
		if (!cnt)
			break;
		l += cnt;
	}
	fclose(i);
	text = realloc(text, l + 1);
	if (!text)
		return NULL;
	text[l] = '\0';

	/* Check current System ARG_MAX limit. */
	if (l > 0.80 * (cnt = sysconf(_SC_ARG_MAX))) {
		fprintf(stderr, "%s: WARNING!!\n"
"   Scripts of length near to (or higher than) the current System limit on\n"
"   \"maximum size of arguments to EXEC\", could comprise its binary execution.\n"
"   In the current System the call sysconf(_SC_ARG_MAX) returns %d bytes\n"
"   and your script \"%s\" is %d bytes length.\n",
		my_name, cnt, file, l);
	}
	return text;
}

unsigned rand_mod(unsigned mod)
{
	/* Without skew */
	unsigned rnd, top = RAND_MAX;
	top -= top % mod;
	while (top <= (rnd = rand()))
		continue;
	/* Using high-order bits. */
	rnd = 1.0*mod*rnd/(1.0+top);
	return rnd;
}

char rand_chr(void)
{
	return (char)rand_mod(1<<(sizeof(char)<<3));
}

int noise(char * ptr, unsigned min, unsigned xtra, int str)
{
	if (xtra) xtra = rand_mod(xtra);
	xtra += min;
	for (min = 0; min < xtra; min++, ptr++)
		do
			*ptr = rand_chr();
		while (str && !isalnum((int)*ptr));
	if (str) *ptr = '\0';
	return xtra;
}

static int offset;
static const char * data_var_name = "data";

void prnt_bytes(FILE * o, char * ptr, int m, int l, int n)
{
	int i;

	l += m;
	n += l;
	for (i = 0; i < n; i++) {
		if ((i & 0xf) == 0)
			fprintf(o, "\n\t\"");
		fprintf(o, "\\x%02x", (unsigned char)((i>=m) && (i<l) ? ptr[i-m] : rand_chr()));
		if ((i & 0xf) == 0xf)
			fprintf(o, "\"");
	}
	if ((i & 0xf) != 0)
		fprintf(o, "\"");
	offset += n;
}

void prnt_array(FILE * o, void * ptr, char * name, int l, char * cast)
{
	int m = rand_mod(1+l/4);		/* Random amount of random pre  padding (offset) */
	int n = rand_mod(1+l/4);		/* Random amount of random post padding  (tail)  */
	int a = (offset+m)%l;
	if (cast && a) m += l - a;		/* Type alignement. */
	fprintf(o, "\n");
	fprintf(o, "#define      %s_z	%d", name, l);
	fprintf(o, "\n");
	fprintf(o, "#define      %s	(%s(&%s[%d]))", name, cast?cast:"", data_var_name, offset+m);
	prnt_bytes(o, ptr, m, l, n);
}

void dump_array(FILE * o, void * ptr, char * name, int l, char * cast)
{
	cc_crypt_impl(ptr, l);
	prnt_array(o, ptr, name, l, cast);
}

int write_C(char * file, char * argv[])
{
	char pswd[640]; /* 128 K_local + up to 512 key material */
	int pswd_z = 256; /* default: full 256-byte password */
	char* msg1 = strdup("has expired!\n");
	int msg1_z = strlen(msg1) + 1;
	int date_z = strlen(date) + 1;
	char* kwsh = strdup(shll);
	int shll_z = strlen(shll) + 1;
	int inlo_z = strlen(inlo) + 1;
	int xecc_z = strlen(xecc) + 1;
	int lsto_z = strlen(lsto) + 1;
	char* tst1 = strdup("location has changed!");
	int tst1_z = strlen(tst1) + 1;
	char* chk1 = calloc(16, 1);
	int chk1_z = 16;
	char* msg2 = strdup("abnormal behavior!");
	int msg2_z = strlen(msg2) + 1;
	int rlax_z = sizeof(rlax);
	int opts_z = strlen(opts) + 1;
	int text_z = strlen(text) + 1;
	char* tst2 = strdup("shell has changed!");
	int tst2_z = strlen(tst2) + 1;
	char* chk2 = calloc(16, 1);
	int chk2_z = 16;
	char* name = strdup(file);
	FILE * o;
	int indx;
	int numd = 0;
	int done = 0;

	/* Encrypt */
	{
		/* Seed from /dev/urandom if available */
		FILE * urand = fopen("/dev/urandom", "r");
		if (urand) {
			unsigned seed;
			if (fread(pswd, 1, 256, urand) != 256)
				memset(pswd, 0, 256); /* fallback below */
			if (fread(&seed, sizeof(seed), 1, urand) == 1)
				srand(seed);
			else
				srand((unsigned)time(NULL)^(unsigned)getpid());
			fclose(urand);
		} else {
			srand((unsigned)time(NULL)^(unsigned)getpid());
			noise(pswd, 256, 0, 0);
		}
	}

	/* Generate random runtime names and cipher parameters */
	struct rt_names rtn;
	init_rt_names(&rtn);
	data_var_name = rtn.data_var;

	/* Set compiler-side cipher to use the same random parameters */
	cc_cp = &rtn.cp;

	numd++;
	cc_init();
	if (REMOTE_KEY_flag) {
		/* K_local only for metadata — K_remote mixed in after metadata */
		cc_key_mix_impl(pswd, 128);
	} else {
		cc_key_mix_impl(pswd, pswd_z);
	}
	if (date[0]) {
		/* Expiration is set — include expiry message + mail contact */
		msg1_z += strlen(mail);
		msg1 = strcat(realloc(msg1, msg1_z), mail);
		cc_crypt_impl(msg1, msg1_z); numd++;
		cc_crypt_impl(date, date_z); numd++;
	} else {
		/* No expiration — skip msg1/date entirely, no arrays emitted */
		msg1_z = -1;
		date_z = -1;
	}
	cc_crypt_impl(shll, shll_z); numd++;
	cc_crypt_impl(inlo, inlo_z); numd++;
	cc_crypt_impl(xecc, xecc_z); numd++;
	cc_crypt_impl(lsto, lsto_z); numd++;
	/* MAC-based integrity: compute tag of plaintext tst1 before encrypting it */
	cc_mac_impl(tst1, tst1_z, (unsigned char *)chk1); numd++;
	cc_crypt_impl(tst1, tst1_z); numd++;
	cc_crypt_impl(msg2, msg2_z); numd++;
	indx = !rlax[0];
	cc_crypt_impl(rlax, rlax_z); numd++;
	if (indx && key_with_file(kwsh)) {
		fprintf(stderr, "%s: invalid file name: %s ", my_name, kwsh);
		perror("");
		exit(1);
	}
	cc_crypt_impl(opts, opts_z); numd++;

	/* Deniability and non-deniability paths for text encryption */
	char * txt0 = NULL; int txt0_z = 0;
	char * txt1 = NULL; int txt1_z = 0;
	char * mac0 = NULL; int mac0_z = 0;
	char * mac1 = NULL; int mac1_z = 0;
	char * chk0 = NULL; int chk0_z = 0;
	char * chk1b = NULL; int chk1b_z = 0;

	if (DENIABILITY_flag) {
		/* Read decoy script */
		decoy_text = read_script(decoy_file);
		if (!decoy_text) {
			fprintf(stderr, "%s: cannot read decoy script: %s\n", my_name, decoy_file);
			exit(1);
		}

		/* Generate K_decoy (69 bytes) and K_real (420 bytes) from urandom */
		char k_decoy[CC_RACHIS_SZ];
		char k_real[CC_VANES_SZ];
		{
			FILE * urand = fopen("/dev/urandom", "r");
			if (!urand || fread(k_decoy, 1, CC_RACHIS_SZ, urand) != CC_RACHIS_SZ
				|| fread(k_real, 1, CC_VANES_SZ, urand) != CC_VANES_SZ) {
				fprintf(stderr, "%s: failed to read /dev/urandom for deniability keys\n", my_name);
				exit(1);
			}
			fclose(urand);
		}

		/* Save cipher state S_pre (after opts, before text) */
		struct cc_state s_pre;
		cc_save_state(&s_pre);

		/* Branch A: real text with K_real */
		int real_text_z = strlen(text) + 1;
		char * real_text = malloc(real_text_z);
		memcpy(real_text, text, real_text_z);
		char * real_tst = strdup("shell has changed!");
		int real_tst_z = strlen(real_tst) + 1;
		char * real_chk = calloc(16, 1);

		cc_key_mix_impl(k_real, CC_VANES_SZ);
		cc_crypt_impl(real_text, real_text_z);
		cc_mac_impl(real_tst, real_tst_z, (unsigned char *)real_chk);
		cc_crypt_impl(real_tst, real_tst_z);

		/* Restore state S_pre */
		cc_restore_state(&s_pre);

		/* Branch B: decoy text with K_decoy */
		int decoy_text_z = strlen(decoy_text) + 1;
		char * decoy_text_enc = malloc(decoy_text_z);
		memcpy(decoy_text_enc, decoy_text, decoy_text_z);
		char * decoy_tst = strdup("shell has changed!");
		int decoy_tst_z = strlen(decoy_tst) + 1;
		char * decoy_chk = calloc(16, 1);

		cc_key_mix_impl(k_decoy, CC_RACHIS_SZ);
		cc_crypt_impl(decoy_text_enc, decoy_text_z);
		cc_mac_impl(decoy_tst, decoy_tst_z, (unsigned char *)decoy_chk);
		cc_crypt_impl(decoy_tst, decoy_tst_z);

		/* Randomly assign real/decoy to txt0/txt1 */
		int real_first = rand_mod(2);
		if (real_first) {
			txt0 = real_text; txt0_z = real_text_z;
			mac0 = real_tst; mac0_z = real_tst_z;
			chk0 = real_chk; chk0_z = 16;
			txt1 = decoy_text_enc; txt1_z = decoy_text_z;
			mac1 = decoy_tst; mac1_z = decoy_tst_z;
			chk1b = decoy_chk; chk1b_z = 16;
		} else {
			txt0 = decoy_text_enc; txt0_z = decoy_text_z;
			mac0 = decoy_tst; mac0_z = decoy_tst_z;
			chk0 = decoy_chk; chk0_z = 16;
			txt1 = real_text; txt1_z = real_text_z;
			mac1 = real_tst; mac1_z = real_tst_z;
			chk1b = real_chk; chk1b_z = 16;
		}
		numd += 6; /* txt0, mac0, chk0, txt1, mac1, chk1b */

		/* Store K_decoy and K_real for .key file (written below) */
		/* Use pswd+128 area to stash K_decoy and K_real temporarily */
		memcpy(pswd + 128, k_decoy, CC_RACHIS_SZ);
		memcpy(pswd + 128 + CC_RACHIS_SZ, k_real, CC_VANES_SZ);
	} else {
		if (REMOTE_KEY_flag) {
			/* Non-deniability remote: mix K_remote after metadata, before text */
			cc_key_mix_impl(pswd + 128, 128);
		}
		cc_crypt_impl(text, text_z); numd++;
		/* MAC-based integrity for tst2 */
		cc_mac_impl(tst2, tst2_z, (unsigned char *)chk2); numd++;
		cc_crypt_impl(tst2, tst2_z); numd++;
	}

	/* Remote key-split: generate auxiliary data */
	char binary_id[16];
	int binary_id_z = 0;
	char psk[32];
	int psk_z = 0;
	char * rhost_enc = NULL;
	int rhost_z = 0;
	char rport_buf[8];
	int rport_z = 0;

	if (REMOTE_KEY_flag) {
		/* Generate binary_id and psk from urandom */
		{
			FILE * urand = fopen("/dev/urandom", "r");
			if (!urand || fread(binary_id, 1, 16, urand) != 16
				|| fread(psk, 1, 32, urand) != 32) {
				fprintf(stderr, "%s: failed to read /dev/urandom for remote key\n", my_name);
				exit(1);
			}
			fclose(urand);
		}
		binary_id_z = 16;
		psk_z = 32;

		/* Write .key file */
		{
			char * keyfile = malloc(strlen(file) + 5);
			sprintf(keyfile, "%s.key", file);
			FILE * kf = fopen(keyfile, "w");
			if (!kf) {
				fprintf(stderr, "%s: cannot create key file: %s ", my_name, keyfile);
				perror("");
				exit(1);
			}
			fprintf(kf, "{\n  \"binary_id\": \"");
			{ int ki; for (ki = 0; ki < 16; ki++) fprintf(kf, "%02x", (unsigned char)binary_id[ki]); }
			if (DENIABILITY_flag) {
				fprintf(kf, "\",\n  \"k_decoy\": \"");
				{ int ki; for (ki = 0; ki < CC_RACHIS_SZ; ki++) fprintf(kf, "%02x", (unsigned char)pswd[128 + ki]); }
				fprintf(kf, "\",\n  \"k_real\": \"");
				{ int ki; for (ki = 0; ki < CC_VANES_SZ; ki++) fprintf(kf, "%02x", (unsigned char)pswd[128 + CC_RACHIS_SZ + ki]); }
				fprintf(kf, "\",\n  \"deniability\": true,\n");
			} else {
				fprintf(kf, "\",\n  \"k_remote\": \"");
				{ int ki; for (ki = 128; ki < 256; ki++) fprintf(kf, "%02x", (unsigned char)pswd[ki]); }
				fprintf(kf, "\",\n");
			}
			fprintf(kf, "  \"psk\": \"");
			{ int ki; for (ki = 0; ki < 32; ki++) fprintf(kf, "%02x", (unsigned char)psk[ki]); }
			fprintf(kf, "\",\n  \"sboxes\": [");
			{ int si, bi;
			  for (si = 0; si < CC_NSBOX; si++) {
				fprintf(kf, "\"");
				for (bi = 0; bi < 256; bi++) fprintf(kf, "%02x", rtn.cp.sbox[si][bi]);
				fprintf(kf, "\"%s", si < CC_NSBOX - 1 ? "," : "");
			  }
			}
			fprintf(kf, "],\n  \"vane_perm\": [");
			{ int vi, bi;
			  for (vi = 0; vi < CC_VANE_SEGS; vi++) {
				fprintf(kf, "\"");
				for (bi = 0; bi < CC_VANE_SEG_SZ; bi++) fprintf(kf, "%02x", rtn.cp.vane_perm[vi][bi]);
				fprintf(kf, "\"%s", vi < CC_VANE_SEGS - 1 ? "," : "");
			  }
			}
			fprintf(kf, "],\n  \"layer_const\": \"");
			{ int li, bi; for (li = 0; li < rtn.cp.nlayers; li++) for (bi = 0; bi < 16; bi++) fprintf(kf, "%02x", rtn.cp.layer_const[li][bi]); }
			fprintf(kf, "\",\n  \"nlayers\": %d\n}\n", rtn.cp.nlayers);
			fclose(kf);
			if (verbose) fprintf(stderr, "%s: wrote key file: %s\n", my_name, keyfile);
			free(keyfile);
		}

		/* Truncate pswd to K_local = pswd[0..127] for embedding */
		pswd_z = 128;

		/* Encode host and port for embedding */
		rhost_z = strlen(remote_host) + 1;
		rhost_enc = strdup(remote_host);
		snprintf(rport_buf, sizeof(rport_buf), "%d", remote_port);
		rport_z = strlen(rport_buf) + 1;
	}

	name = strcat(realloc(name, strlen(name)+5), ".x.c");
	o = fopen(name, "w");
	if (!o) {
		fprintf(stderr, "%s: creating output file: %s ", my_name, name);
		perror("");
		exit(1);
	}
	fprintf(o, "static  char %s [] = ", rtn.data_var);
	if (DENIABILITY_flag) {
		/* In deniability mode: emit base fields + dual text blobs */
		do {
			done = 0;
			indx = rand_mod(18);
			do {
				switch (indx) {
				case  0: if (pswd_z>=0) {prnt_array(o, pswd, "pswd", pswd_z, 0); pswd_z=done=-1; break;}
				case  1: if (msg1_z>=0) {prnt_array(o, msg1, "msg1", msg1_z, 0); msg1_z=done=-1; break;}
				case  2: if (date_z>=0) {prnt_array(o, date, "date", date_z, 0); date_z=done=-1; break;}
				case  3: if (shll_z>=0) {prnt_array(o, shll, "shll", shll_z, 0); shll_z=done=-1; break;}
				case  4: if (inlo_z>=0) {prnt_array(o, inlo, "inlo", inlo_z, 0); inlo_z=done=-1; break;}
				case  5: if (xecc_z>=0) {prnt_array(o, xecc, "xecc", xecc_z, 0); xecc_z=done=-1; break;}
				case  6: if (lsto_z>=0) {prnt_array(o, lsto, "lsto", lsto_z, 0); lsto_z=done=-1; break;}
				case  7: if (tst1_z>=0) {prnt_array(o, tst1, "tst1", tst1_z, 0); tst1_z=done=-1; break;}
				case  8: if (chk1_z>=0) {prnt_array(o, chk1, "chk1", chk1_z, 0); chk1_z=done=-1; break;}
				case  9: if (msg2_z>=0) {prnt_array(o, msg2, "msg2", msg2_z, 0); msg2_z=done=-1; break;}
				case 10: if (rlax_z>=0) {prnt_array(o, rlax, "rlax", rlax_z, 0); rlax_z=done=-1; break;}
				case 11: if (opts_z>=0) {prnt_array(o, opts, "opts", opts_z, 0); opts_z=done=-1; break;}
				case 12: if (txt0_z>=0) {prnt_array(o, txt0, "txt0", txt0_z, 0); txt0_z=done=-1; break;}
				case 13: if (mac0_z>=0) {prnt_array(o, mac0, "mac0", mac0_z, 0); mac0_z=done=-1; break;}
				case 14: if (chk0_z>=0) {prnt_array(o, chk0, "chk0", chk0_z, 0); chk0_z=done=-1; break;}
				case 15: if (txt1_z>=0) {prnt_array(o, txt1, "txt1", txt1_z, 0); txt1_z=done=-1; break;}
				case 16: if (mac1_z>=0) {prnt_array(o, mac1, "mac1", mac1_z, 0); mac1_z=done=-1; break;}
				case 17: if (chk1b_z>=0) {prnt_array(o, chk1b, "chk1b", chk1b_z, 0); chk1b_z=done=-1; break;}
				}
				indx = 0;
			} while (!done);
		} while (numd+=done);
	} else {
		do {
			done = 0;
			indx = rand_mod(15);
			do {
				switch (indx) {
				case  0: if (pswd_z>=0) {prnt_array(o, pswd, "pswd", pswd_z, 0); pswd_z=done=-1; break;}
				case  1: if (msg1_z>=0) {prnt_array(o, msg1, "msg1", msg1_z, 0); msg1_z=done=-1; break;}
				case  2: if (date_z>=0) {prnt_array(o, date, "date", date_z, 0); date_z=done=-1; break;}
				case  3: if (shll_z>=0) {prnt_array(o, shll, "shll", shll_z, 0); shll_z=done=-1; break;}
				case  4: if (inlo_z>=0) {prnt_array(o, inlo, "inlo", inlo_z, 0); inlo_z=done=-1; break;}
				case  5: if (xecc_z>=0) {prnt_array(o, xecc, "xecc", xecc_z, 0); xecc_z=done=-1; break;}
				case  6: if (lsto_z>=0) {prnt_array(o, lsto, "lsto", lsto_z, 0); lsto_z=done=-1; break;}
				case  7: if (tst1_z>=0) {prnt_array(o, tst1, "tst1", tst1_z, 0); tst1_z=done=-1; break;}
				case  8: if (chk1_z>=0) {prnt_array(o, chk1, "chk1", chk1_z, 0); chk1_z=done=-1; break;}
				case  9: if (msg2_z>=0) {prnt_array(o, msg2, "msg2", msg2_z, 0); msg2_z=done=-1; break;}
				case 10: if (rlax_z>=0) {prnt_array(o, rlax, "rlax", rlax_z, 0); rlax_z=done=-1; break;}
				case 11: if (opts_z>=0) {prnt_array(o, opts, "opts", opts_z, 0); opts_z=done=-1; break;}
				case 12: if (text_z>=0) {prnt_array(o, text, "text", text_z, 0); text_z=done=-1; break;}
				case 13: if (tst2_z>=0) {prnt_array(o, tst2, "tst2", tst2_z, 0); tst2_z=done=-1; break;}
				case 14: if (chk2_z>=0) {prnt_array(o, chk2, "chk2", chk2_z, 0); chk2_z=done=-1; break;}
				}
				indx = 0;
			} while (!done);
		} while (numd+=done);
	}
	fprintf(o, ";\n");
	/* Emit remote key XOR-encoded arrays if in remote mode */
	if (REMOTE_KEY_flag) {
		char vn[32];
		snprintf(vn, sizeof(vn), "%s_binid", rtn.xor_prefix);
		emit_xor_binary(o, vn, binary_id, 16);
		snprintf(vn, sizeof(vn), "%s_psk", rtn.xor_prefix);
		emit_xor_binary(o, vn, psk, 32);
		snprintf(vn, sizeof(vn), "%s_rhost", rtn.xor_prefix);
		emit_xor_binary(o, vn, rhost_enc, rhost_z);
		snprintf(vn, sizeof(vn), "%s_rport", rtn.xor_prefix);
		emit_xor_binary(o, vn, rport_buf, rport_z);
	}
	fprintf(o, "#define      %s_z	%d\n", "hide", 1<<12);
	fprintf(o, SETUID_line, SETUID_flag);
	fprintf(o, DEBUGEXEC_line, DEBUGEXEC_flag);
	fprintf(o, TRACEABLE_line, TRACEABLE_flag);
	fprintf(o, HARDENING_line, HARDENING_flag);
	fprintf(o, BUSYBOXON_line, BUSYBOXON_flag);
	fprintf(o, MMAP2_line, MMAP2_flag);
	fprintf(o, REMOTE_KEY_line, REMOTE_KEY_flag);
	fprintf(o, DENIABILITY_line, DENIABILITY_flag);
	emit_runtime(o, &rtn);
	fflush(o);
	fclose(o);

	return 0;
}

int make(void)
{
	char * cc, * cflags, * ldflags;
	char cmd[SIZE];

	cc = getenv("CC");
	if (!cc)
		cc = "cc";
	cflags = getenv("CFLAGS");
	if (!cflags)
		cflags = "";
	ldflags = getenv("LDFLAGS");
	if (!ldflags)
		ldflags = "";

if(!file2){
file2=(char*)realloc(file2,strlen(file)+3);
strcpy(file2,file);
file2=strcat(file2,".x");

}
	sprintf(cmd, "%s %s %s -ldl %s.x.c -o %s", cc, cflags, ldflags, file, file2);
	if (verbose) fprintf(stderr, "%s: %s\n", my_name, cmd);
	if (system(cmd))
		return -1;
	char* strip = getenv("STRIP");
	if (!strip)
		strip = "strip";
	sprintf(cmd, "%s %s", strip, file2);
	if (verbose) fprintf(stderr, "%s: %s\n", my_name, cmd);
	if (system(cmd))
		fprintf(stderr, "%s: never mind\n", my_name);
	sprintf(cmd, "chmod ug=rwx,o=rx %s", file2);
	if (verbose) fprintf(stderr, "%s: %s\n", my_name, cmd);
	if (system(cmd))
		fprintf(stderr, "%s: remove read permission\n", my_name);

	return 0;
}

void do_all(int argc, char * argv[])
{
	parse_args(argc, argv);
	if (DENIABILITY_flag && !REMOTE_KEY_flag) {
		fprintf(stderr, "%s: -d requires -R (remote key server)\n", my_name);
		exit(1);
	}
	text = read_script(file);
	if (!text)
		return;
	if (eval_shell(text))
		return;
	if (write_C(file, argv))
		return;
	if (make())
		return;
	exit(0);
}

int main(int argc, char * argv[])
{
	putenv("LANG=");
	do_all(argc, argv);
	/* Return on error */
	perror(argv[0]);
	exit(1);
	return 1;
}

