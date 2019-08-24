#include <stdio.h>
#include <sodium.h>
#include <getopt.h>
#include "key_file.h"
#include "file_sym_enc.h"

void help(void)
{
	puts("MalaCryptor Help:");
	puts("\tOptions:");
	puts("\t\t-g [file path], to generate a new key, and store it in the specified file.");
	puts("\t\t-e [sourcefile] -o [out file] -k [key file] to encrypt a file using a key file");
	puts("\t\t-d [sourcefile] -o [out file] -k [key file] to decrypt a file using a key file");
	puts("\t\t-h for help");
}

int main(int arg_count, char *arguments[])
{
	key_file_generate_keypair("pkey_file", "skey_file", key_file_hybrid);
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
	//encrypt arguments
	char encrypt_flag = 0;
	char *encrypt_file_path = NULL;
	//decrypt arguments
	char decrypt_flag = 0;
	char *decrypt_file_path = NULL;
	//output file arguments
	char output_flag = 0;
	char *output_file_path = NULL;
	//key file arguments
	char key_file_flag = 0;
	char *key_file_path = NULL;
	//current argument to be parsed
	int current_arg;
	while ((current_arg = getopt(arg_count, arguments, "g:e:o:k:d:h")) !=
	       -1) {
		switch (current_arg) {
		case 'h': {
			help();
			return 0;
		}
		case 'g': {
			key_file_generate_sym(optarg);
			break;
		}
		case 'e': {
			encrypt_flag = 1;
			encrypt_file_path = optarg;
			break;
		}
		case 'd': {
			decrypt_flag = 1;
			decrypt_file_path = optarg;
			break;
		}
		case 'o': {
			output_flag = 1;
			output_file_path = optarg;
			break;
		}
		case 'k': {
			key_file_flag = 1;
			key_file_path = optarg;
			break;
		}
		case '?': {
			help();
			return 0;
		}
		}
	}
	//operations to do if encrypting, or decrypting a file.
	if (decrypt_flag || encrypt_flag) {
		int out_and_key_valid =
			((output_flag) && (output_file_path != NULL) &&
			 (key_file_flag) && (key_file_path != NULL));
		//encrypt a file, if all the valid flags are set
		if (encrypt_flag) {
			if ((encrypt_file_path != NULL) && out_and_key_valid) {
				if (file_sym_enc_encrypt_key_file(
					    output_file_path, encrypt_file_path,
					    key_file_path) != 0) {
					fputs("An error occurred while encrypting the file.\n",
					      stderr);
					return 1;
				}
			} else {
				help();
			}
			//decrypt a file, if all the valid flags are set
		} else if (decrypt_flag) {
			if ((decrypt_flag) && (decrypt_file_path != NULL) &&
			    out_and_key_valid) {
				if (file_sym_enc_decrypt_key_file(
					    output_file_path, decrypt_file_path,
					    key_file_path) != 0) {
					fputs("An error occurred while decrypting the file.\n",
					      stderr);
					return 1;
				}
			} else {
				help();
			}
		}
	}
	return 0;
}
