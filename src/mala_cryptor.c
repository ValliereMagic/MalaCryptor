#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include <stdarg.h>
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

// Check whether the current opt(key) matched the arg_key(value) and
// there are enough arguments afterwords to satisfy the values
// it requires (has_next)
static unsigned char is_opt(const char *key, const char *value,
			    const unsigned char has_next)
{
	if ((strcmp(key, value) == 0)) {
		if (!has_next) {
			fprintf(stderr,
				"Error. Option '%s' requires one or more argument(s). "
				"Exiting.\n",
				key);
			return 0;
		}
		return 1;
	}
	return 0;
}

// Make sure the value isn't another argument
// (starts with [-]) otherwise error
static inline unsigned char check_optarg_val(const char *value)
{
	// make sure that value doesn't start with '-'
	// This can't happen, otherwise not a valid value
	if (value[0] == '-')
		return 0;
	return 1;
}

// num_vals is the number of arguments that the callback takes
// arg_key is the argument we are checking the values for
// arguments[] is the full array of command line arguments
// index is the current iteration index of the arguments array
// arg count is the total number of elements in arguments[]
// callback is the callback to call with num_vals number of arguments
// (in the values array)
// keypair is set to 0 or 1 depending if we are generating a public / private
// keypair or not. If 0 the value of keypair_type doesn't matter.
// keypair_type is the type of keypair to generate.
// num_vals CANNOT BE LARGER THAN MAX_VALUES
// return values
// 0 no argument processed, or an error occured.
// If an error occurred a print statement must accompany it to signify
// that an error actually occurred.
// 1 argument successfully processed and operated on.
#define MAX_VALUES 3
static unsigned char parse_args_vals_call(size_t num_vals, const char *arg_key,
					  char *arguments[], int index,
					  int arg_count, void (*callback)(),
					  unsigned char keypair,
					  enum keypair_type keypair_type)
{
	// General format for error messages.
	static const char *error_fmt =
		"Error. Invalid or no argument(s) for '%s'. Exiting.\n";
	// Make sure there is room for an option after this string
	const unsigned char args_left = (arg_count - 1) - index;
	// Current possible argument to look at
	const char *current_argument = arguments[index];
	// one to max values values for the argument being parsed.
	// values to pass to the callback
	static const char *values[MAX_VALUES];
	// Check whether the current opt matched the arg_key and
	// there are enough arguments afterwords to satisfy the values
	// it requires
	if (is_opt(current_argument, arg_key, (args_left >= num_vals))) {
		// Make sure the proposed values for the argument make
		// sense.
		for (size_t i = 0; i < num_vals; i++) {
			// set the value at i as the supposed value
			// of the argument (-foo bar bar bar)
			values[i] = arguments[index + (i + 1)];
			// Make sure the value isn't another argument
			// (starts with [-]) otherwise error
			if (!check_optarg_val(values[i])) {
				// failure
				fprintf(stderr, error_fmt, arg_key);
				return 0;
			}
		}
		// call the callback as such. Each value for MAX_VALUES must have
		// a case (1 to MAX_VALUES)
		switch (num_vals) {
		case 0:
			callback();
			break;
		case 1:
			callback(values[0]);
			break;
		case 2: {
			// If we are dealing with keypairs, need to specify keypair
			// type. Only do this if keypair is true (generating a PKI keypair).
			if (keypair)
				callback(values[0], values[1], keypair_type);
			else
				callback(values[0], values[1]);
			break;
		}
		case 3:
			callback(values[0], values[1], values[2]);
			break;
		}
		// operated on argument successfully.
		return 1;
	}
	// Did not operate on an argument, but not a failure.
	return 0;
}

static unsigned char parse_ops_exec(int arg_count, char *arguments[])
{
	// valid arguments for program operations
	static const char *valid_args[] = { "-h",
					    "-gen_sym_key_file",
					    "-sym_enc_file",
					    "-sym_dec_file",
					    "-gen_classical_keypair",
					    "-gen_quantum_keypair",
					    "-gen_hybrid_keypair" };
	// Set to true if an argument exists and was executed successfully
	// (parse || arg_executed) so its true even if only one arg is ever
	// executed.
	unsigned char arg_executed = 0;
	for (int i = 0; i < arg_count; i++) {
		// Check whether the current argument is a valid program operation
		// generate symmetric keyfile.
		// Help argument
		arg_executed = parse_args_vals_call(0, valid_args[0], arguments,
						    i, arg_count,
						    (void (*)())help, 0, 0) ||
			       arg_executed;
		// generate symmetric key file
		arg_executed =
			parse_args_vals_call(1, valid_args[1], arguments, i,
					     arg_count,
					     (void (*)())key_file_generate_sym,
					     0, 0) ||
			arg_executed;
		// encrypt file with symmetric key file
		arg_executed =
			parse_args_vals_call(
				3, valid_args[2], arguments, i, arg_count,
				(void (*)())file_sym_enc_encrypt_key_file, 0,
				0) ||
			arg_executed;
		// decrypt file with symmetric key file
		arg_executed =
			parse_args_vals_call(
				3, valid_args[3], arguments, i, arg_count,
				(void (*)())file_sym_enc_decrypt_key_file, 0,
				0) ||
			arg_executed;
		// generate classical keypair
		arg_executed =
			parse_args_vals_call(
				2, valid_args[4], arguments, i, arg_count,
				(void (*)())key_file_generate_keypair, 1,
				key_file_classical) ||
			arg_executed;
		// generate quantum keypair
		arg_executed =
			parse_args_vals_call(
				2, valid_args[5], arguments, i, arg_count,
				(void (*)())key_file_generate_keypair, 1,
				key_file_quantum) ||
			arg_executed;
		// generate hybrid keypair
		arg_executed =
			parse_args_vals_call(
				2, valid_args[6], arguments, i, arg_count,
				(void (*)())key_file_generate_keypair, 1,
				key_file_hybrid) ||
			arg_executed;
	}
	// no recognized argument was executed. Or failure.
	if (!arg_executed)
		puts("Argument or value not recognised. Try '-h'.");
	return 1;
}

int main(int arg_count, char *arguments[])
{
	//if the user doesn't specify an argument, present the help screen.
	if (arg_count == 1) {
		help();
		return EXIT_SUCCESS;
	}
	//Initiate libsodium.
	if (sodium_init() < 0) {
		fputs("Error. Unable to initiate libsodium. Exiting.\n",
		      stderr);
		return 1;
	}
	// Begin operations
	if (!parse_ops_exec(arg_count, arguments)) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
