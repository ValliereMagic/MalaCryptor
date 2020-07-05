#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include "key_file.h"
#include "file_sym_enc.h"

struct parsable_argument {
	// Number of values this argument takes
	size_t num_vals;
	// The string key for this argument
	const char *arg_key;
	// Callback to call with the values
	// of this argument
	void (*callback)();
	// Boolean value for whether this argument
	// generates a public / private keypair
	unsigned char keypair;
	// enum representing the keypair type
	// 0 of keypair bool is 0. Otherwise
	// specify valid keypair type.
	enum keypair_type keypair_type;
};

// Check whether the current opt(key) matched the arg_key(value) and
// there are enough arguments afterwords to satisfy the values
// it requires (has_next)
static unsigned char is_opt(const char *key, const char *value,
			    const unsigned char has_next)
{
	// make sure that the key and the value(arg from arguments
	// string) match.
	if (!(strcmp(key, value) == 0))
		return 0;
	// Make sure there are enough values to satisfy the argument
	if (!has_next) {
		fprintf(stderr,
			"Error. Option '%s' requires one or more argument(s). "
			"Exiting.\n",
			key);
		return 0;
	}
	return 1;
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
//
// index is a pointer to the current iteration index of the arguments array.
// it is to be incremented by the number of values the current argument has
// so that they are not parsed and checked to see if they are commands.
//
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
static unsigned char
parse_args_vals_call(const struct parsable_argument *const arg,
		     char *arguments[], int *index, int arg_count)
{
	// General format for error messages.
	static const char *const error_fmt =
		"Error. Invalid or no argument(s) for '%s'. Exiting.\n";
	// Make sure there is room for an option after this string
	const unsigned char args_left = (arg_count - 1) - (*index);
	// Current possible argument to look at
	const char *current_argument = arguments[*index];
	// one to max values values for the argument being parsed.
	// values to pass to the callback
	static const char *values[MAX_VALUES];
	// Check whether the current opt matched the arg_key and
	// there are enough arguments afterwords to satisfy the values
	// it requires
	if (!is_opt(current_argument, arg->arg_key,
		    (args_left >= arg->num_vals)))
		// Did not operate on an argument, but not necessarily a failure.
		return 0;
	// Make sure the proposed values for the argument make
	// sense.
	for (size_t i = 0; i < arg->num_vals; i++) {
		// set the value at i as the supposed value
		// of the argument (-foo bar bar bar)
		values[i] = arguments[*index + (i + 1)];
		// Make sure the value isn't another argument
		// (starts with [-]) otherwise error
		if (!check_optarg_val(values[i])) {
			// failure
			fprintf(stderr, error_fmt, arg->arg_key);
			return 0;
		}
	}
	// call the callback as such. Each value for MAX_VALUES must have
	// a case (1 to MAX_VALUES)
	switch (arg->num_vals) {
	case 0:
		arg->callback();
		break;
	case 1:
		arg->callback(values[0]);
		break;
	case 2: {
		// If we are dealing with keypairs, need to specify keypair
		// type. Only do this if keypair is true (generating a PKI keypair).
		if (arg->keypair)
			arg->callback(values[0], values[1], arg->keypair_type);
		else
			arg->callback(values[0], values[1]);
		break;
	}
	case 3:
		arg->callback(values[0], values[1], values[2]);
		break;
	}
	// increment index to not check the arguments of the current
	// command as a new command.
	(*index) += arg->num_vals;
	// operated on argument successfully.
	return 1;
}

void help(void)
{
	puts("MalaCryptor Help:");

	puts("\t-h for help");

	puts("\tSymmetric File Encryption Options:");

	puts("\t\t-gen_sym_key_file [file path], to generate a new key, and\n"
	     "\t\t\tstore it in the specified file.");

	puts("\t\t-sym_enc_file [sourcefile] [out file] [key file] to encrypt\n"
	     "\t\t\ta file using a key file");

	puts("\t\t-sym_pass_enc_file [sourcefile] [out file]\n"
	     "\t\t\t(Password prompt will be next...)\n"
	     "\t\t\tto encrypt a file using a password");

	puts("\t\t-sym_dec_file [sourcefile] [out file] [key file] to decrypt\n"
	     "\t\t\ta file using a key file");

	puts("\t\t-sym_pass_dec_file [sourcefile] [out file]\n"
	     "\t\t\t(Password prompt will be next...)\n"
	     "\t\t\tto decrypt a file using a password");

	puts("\tPublic-Private File Encryption Options:");

	puts("\t\t-gen_classical_keypair [public key path] [private key path],\n"
	     "\t\t\t to generate a new classical public-private keypair");

	puts("\t\t-gen_quantum_keypair [public key path] [private key path],\n"
	     "\t\t\tto generate a new quantum resistant keypair");

	puts("\t\t-gen_hybrid_keypair [public key path] [private key path],\n"
	     "\t\t\tto generate a new quantum resistant, and classical\n"
	     "\t\t\tkeypair in one file");
}

static unsigned char parse_ops_exec(int arg_count, char *arguments[])
{
	// The possible arguments to be processed:
	static const struct parsable_argument parsable_arguments[] = {
		// Help argument
		{ .num_vals = 0,
		  .arg_key = "-h",
		  .callback = help,
		  .keypair = 0,
		  .keypair_type = 0 },
		// Generate symmetric key file
		{ .num_vals = 1,
		  .arg_key = "-gen_sym_key_file",
		  .callback = (void (*)())key_file_generate_sym,
		  .keypair = 0,
		  .keypair_type = 0 },
		// Encrypt file with symmetric key file
		{ .num_vals = 3,
		  .arg_key = "-sym_enc_file",
		  .callback = (void (*)())file_sym_enc_encrypt_key_file,
		  .keypair = 0,
		  .keypair_type = 0 },
		// Encrypt file with a provided password
		{ .num_vals = 2,
		  .arg_key = "-sym_pass_enc_file",
		  .callback = (void (*)())file_sym_enc_encrypt_key_password,
		  .keypair = 0,
		  .keypair_type = 0 },
		// Decrypt file with symmetric key file
		{ .num_vals = 3,
		  .arg_key = "-sym_dec_file",
		  .callback = (void (*)())file_sym_enc_decrypt_key_file,
		  .keypair = 0,
		  .keypair_type = 0 },
		// Decrypt file with a provided password
		{ .num_vals = 2,
		  .arg_key = "-sym_pass_dec_file",
		  .callback = (void (*)())file_sym_enc_decrypt_key_password,
		  .keypair = 0,
		  .keypair_type = 0 },
		// Generate a classical keypair
		{ .num_vals = 2,
		  .arg_key = "-gen_classical_keypair",
		  .callback = (void (*)())key_file_generate_keypair,
		  .keypair = 1,
		  .keypair_type = key_file_classical },
		// Generate a quantum keypair
		{ .num_vals = 2,
		  .arg_key = "-gen_quantum_keypair",
		  .callback = (void (*)())key_file_generate_keypair,
		  .keypair = 1,
		  .keypair_type = key_file_quantum },
		// Generate a hybrid keypair
		{ .num_vals = 2,
		  .arg_key = "-gen_hybrid_keypair",
		  .callback = (void (*)())key_file_generate_keypair,
		  .keypair = 1,
		  .keypair_type = key_file_hybrid }

	};
	size_t argument_array_size =
		sizeof(parsable_arguments) / sizeof(parsable_arguments[0]);
	// Set to true if an argument exists and was executed successfully
	// (parse || arg_executed) so its true even if only one arg is ever
	// executed.
	unsigned char arg_executed = 0;
	for (int i = 1; i < arg_count; i++) {
		// Check whether the current argument is a valid program operation,
		// and execute the required callback with its arguments if it is.
		for (size_t j = 0; j < argument_array_size; j++) {
			arg_executed =
				parse_args_vals_call(&parsable_arguments[j],
						     arguments, &i,
						     arg_count) ||
				arg_executed;
		}
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
	if (!parse_ops_exec(arg_count, arguments))
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
