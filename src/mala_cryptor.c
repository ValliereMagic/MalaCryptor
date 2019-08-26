#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include <ctype.h>
#include "key_file.h"
#include "file_sym_enc.h"

void help(void)
{
	puts("MalaCryptor Help:");

	puts("\t-h for help");

	puts("\tSymmetric File Encryption Options:");

	puts("\t\t-gen_sym_key_file [file path], to generate a new key, and\n"
	     "\t\t\tstore it in the specified file.");

	puts("\t\t-sym_enc_file [sourcefile] [out file] [key file] to encrypt\n"
	     "\t\t\ta file using a key file");

	puts("\t\t-sym_dec_file [sourcefile] [out file] [key file] to decrypt\n"
	     "\t\t\ta file using a key file");

	puts("\tPublic-Private File Encryption Options:");

	puts("\t\t-gen_classical_keypair [public key path] [private key path],\n"
	     "\t\t\t to generate a new classical public-private keypair");

	puts("\t\t-gen_quantum_keypair [public key path] [private key path],\n"
	     "\t\t\tto generate a new quantum resistant keypair");

	puts("\t\t-gen_hybrid_keypair [public key path] [private key path],\n"
	     "\t\t\tto generate a new quantum resistant, and classical\n"
	     "\t\t\tkeypair in one file");
}

struct operations {
	// Generate symmetric keyfile
	unsigned char gen_sym_key_file;
	const char *sym_op_key_file;
	// Encrypt file using symmetric keyfile
	// or Decrypt (uses sym_op_key_file)
	unsigned char sym_enc_file;
	unsigned char sym_dec_file;
	const char *sym_op_source_file;
	const char *sym_op_out_file;
};

static unsigned char is_opt(const char *key, const char *value,
			    const unsigned char has_next)
{
	if ((strcmp(key, value) == 0)) {
		if (!has_next) {
			fprintf(stderr, "Error. Option '%s' requires argument(s). Exiting.\n", key);
			return 0;
		}
		return 1;
	}
	return 0;
}

static unsigned char check_optarg_val(char *arg)
{
	// This can't happen, otherwise no arg
	return !(arg[0] == '-');
}

static unsigned char parse_ops(struct operations *ops, int arg_count, char *arguments[])
{
	for (int i = 0; i < arg_count; i++) {
		// Make sure there is room for an option after this string
		const unsigned char args_left = (arg_count - 1) - i;
		// Current possible argument to look at
		const char *current_argument = arguments[i];
		if (is_opt(current_argument, "-gen_sym_key_file",
			   (args_left >= 1))) {
			ops->gen_sym_key_file = 1;
			if (check_optarg_val(arguments[i + 1])) {
				ops->sym_op_key_file = arguments[i + 1];
			} else {
				fputs("Error. Invalid or no argument for '-gen_sym_key_file'. Exiting.\n",
				      stderr);
				return 0;
			}
		}
	}
	return 1;
}

int main(int arg_count, char *arguments[])
{
	//if the user doesn't specify an argument, present the help screen.
	if (arg_count == 1) {
		help();
		return 0;
	}
	//Initiate libsodium.
	if (sodium_init() < 0) {
		fputs("Error. Unable to initiate libsodium. Exiting.\n",
		      stderr);
		return 1;
	}
	// Begin operations
	struct operations ops = { 0, NULL, 0, 0, NULL, NULL };
	unsigned char parse_success = parse_ops(&ops, arg_count, arguments);
	if (!parse_success) {
		return EXIT_FAILURE;
	}
	puts(ops.sym_op_key_file);
	return EXIT_SUCCESS;
}
