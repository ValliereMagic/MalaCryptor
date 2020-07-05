#include <sodium.h>
#include "key_file.h"
#ifdef _WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif
#include "oqs/oqs.h"

// Generate a random key using the function provided by the
// libsodium library and store it in the file at the path passed.
unsigned char key_file_generate_sym(const char *dest_file)
{
	// Make sure our destination file is valid.
	if (dest_file == NULL) {
		return 0;
	}
	unsigned char
		encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	// Lock memory where key is to be stored.
	if (sodium_mlock(encryption_key,
			 crypto_secretstream_xchacha20poly1305_KEYBYTES) != 0) {
		fputs("Error! unable to lock key memory! (key_file_sym)\n",
		      stderr);
		return 0;
	}
	FILE *key_file_new = fopen(dest_file, "wb");
	// Make sure opening the file was successful
	if (key_file_new == NULL) {
		return 0;
	}
	//generate new encryption key for operations
	crypto_secretstream_xchacha20poly1305_keygen(encryption_key);
	//store new encryption key into file
	size_t bytes_written =
		fwrite(encryption_key, 1,
		       crypto_secretstream_xchacha20poly1305_KEYBYTES,
		       key_file_new);
	// Unlock memory where key is stored
	sodium_munlock(encryption_key,
		       crypto_secretstream_xchacha20poly1305_KEYBYTES);
	//print out length (in bytes) of the key written to file.
	printf("%d bytes written to key file.\n", (int)bytes_written);
	//close key file
	fclose(key_file_new);
	return 1;
}

// retrieve the encryption key stored at the path passed
// make sure that the key is the correct length for
// xchacha20
int key_file_get_sym_key(
	const char *key_file_path,
	unsigned char
		encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
	FILE *key_file = fopen(key_file_path, "rb");
	//make sure that the length of the key in key file is correct
	if (!key_file_verify_length(
		    key_file_path,
		    crypto_secretstream_xchacha20poly1305_KEYBYTES)) {
		fclose(key_file);
		return -1;
	}
	//read the key in the key file into the key byte array, and close the file
	fread(encryption_key, 1, crypto_secretstream_xchacha20poly1305_KEYBYTES,
	      key_file);
	fclose(key_file);
	return 1;
}

// Get the length of the file name passed in bytes.
static long key_file_get_size(const char *file_name)
{
	long size;
	FILE *file;
	//open the file in the mode to read bytes
	file = fopen(file_name, "rb");
	//make sure that the file exists.
	if (file == NULL) {
		fprintf(stderr,
			"Error. Unable to determine the size of %s. "
			"File pointer is NULL.\n",
			file_name);
		return -1;
	}
	//go to the end of the file
	fseek(file, 0, SEEK_END);
	//record the length of the file in size
	size = ftell(file);
	//close the file
	fclose(file);
	return size;
}

// verify that the file passed is the correct length to be a key for
// xchacha20poly1305 (256bit == 32bytes)
unsigned short key_file_verify_length(const char *key_file_path,
				      size_t correct_len)
{
	//make sure that the length of the key in key file is correct
	if (key_file_get_size(key_file_path) != correct_len) {
		fputs("Error. the length of the key in the key file is incorrect. Exiting.\n",
		      stderr);
		return 0;
	}
	return 1;
}

struct keypair_gen_info {
	// Keyfiles to write into
	// already at the correct index
	// to begin writing at
	FILE *pkey_file;
	FILE *skey_file;
	// The respective lengths of the
	// public key and the private key
	unsigned short pkey_len;
	unsigned short skey_len;
	// The gen_keypair function, represented in the order
	// pub key, then private key, for generation.
	int (*gen_keypair)(unsigned char *pkey, unsigned char *skey);
	// Handle the result of the gen_keypair function,
	// turning the result into either a 1 for success or a 0
	// for failure.
	int (*handle_error)(int value);
};

// Functions to change the error results into
// the format we want to return.
// 0 means failure, (false);
// 1 means success, (true);
static int handle_OQS_error(int value)
{
	if (value == OQS_SUCCESS)
		return 1;
	return 0;
}

static int handle_sodium_error(int value)
{
	if (value == 0)
		return 1;
	return 0;
}

static unsigned int
key_file_generate_keypair_winfo(struct keypair_gen_info *info)
{
	// Allocate the memory that the keys are going to be stored into.
	unsigned char skey[info->skey_len];
	unsigned char pkey[info->pkey_len];
	// Lock the memory so that it should not be swapped to disk
	if (sodium_mlock(skey, info->skey_len) != 0 ||
	    sodium_mlock(pkey, info->pkey_len) != 0) {
		fputs("Error! unable to lock key memory! (keypair gen)\n",
		      stderr);
	}
	// Generate the keypair into the allocated memory.
	if (!(info->handle_error(info->gen_keypair(pkey, skey)))) {
		fputs("Error! Failure generating the keypair. (keypair gen)\n",
		      stderr);
		return 0;
	}
	// Format the key lengths into network byte order
	uint16_t skey_len = htons(info->skey_len);
	uint16_t pkey_len = htons(info->pkey_len);
	// Write the lengths to the start of the respective files
	fwrite(&skey_len, 2, 1, info->skey_file);
	fwrite(&pkey_len, 2, 1, info->pkey_file);
	// Write the keys to their respective files
	fwrite(skey, 1, skey_len, info->skey_file);
	fwrite(pkey, 1, info->pkey_len, info->pkey_file);
	// Unlock the memory held by the keys, also zeroing them out.
	sodium_munlock(skey, info->skey_len);
	sodium_munlock(pkey, info->pkey_len);
	return 1;
}

// Generate a keypair for sending a file to another person by sending the
// symmetric key using a key encapsulation mechanism
unsigned char key_file_generate_keypair(const char *dest_pkey_file,
					const char *dest_skey_file,
					enum keypair_type type)
{
	// Make sure our destination files are valid
	if ((dest_pkey_file == NULL) || (dest_skey_file == NULL)) {
		return 0;
	}
	// Open key files for writing
	FILE *pkey_file = fopen(dest_pkey_file, "wb");
	FILE *skey_file = fopen(dest_skey_file, "wb");
	// Make sure that the files were successfully opened.
	if ((pkey_file == NULL) || (skey_file == NULL)) {
		return 0;
	}
	// Define the structures detailing how to generate
	// the different types of keypairs.
	struct keypair_gen_info quantum_info = {
		.pkey_file = pkey_file,
		.skey_file = skey_file,
		.pkey_len = OQS_KEM_frodokem_1344_aes_length_public_key,
		.skey_len = OQS_KEM_frodokem_1344_aes_length_secret_key,
		.gen_keypair = OQS_KEM_frodokem_1344_aes_keypair,
		.handle_error = handle_OQS_error
	};
	struct keypair_gen_info classical_info = {
		.pkey_file = pkey_file,
		.skey_file = skey_file,
		.pkey_len = crypto_kx_PUBLICKEYBYTES,
		.skey_len = crypto_kx_PUBLICKEYBYTES,
		.gen_keypair = crypto_kx_keypair,
		.handle_error = handle_sodium_error
	};
	unsigned char success = 1;
	// Choose and generate.
	switch (type) {
	// Generate keypair, and check whether the result was success
	// or failure.
	case key_file_classical:
		success = key_file_generate_keypair_winfo(&classical_info);
		break;
	case key_file_quantum:
		success = key_file_generate_keypair_winfo(&quantum_info);
		break;
	case key_file_hybrid:
		success = key_file_generate_keypair_winfo(&quantum_info);
		success = success &&
			  key_file_generate_keypair_winfo(&classical_info);
		break;
	}
	// We are finished generating the key files, close them.
	fclose(pkey_file);
	fclose(skey_file);
	// Return the outcome
	return success;
}
