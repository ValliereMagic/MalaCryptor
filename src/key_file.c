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

// Generate a quantum keypair using FrodoKEM and store in the
// destination file.
static unsigned char key_file_generate_quantum_keypair(FILE *pkey_file,
						       FILE *skey_file)
{
	// Generate Quantum Resistant KEM keypair
	unsigned char skey[OQS_KEM_frodokem_1344_aes_length_secret_key];
	unsigned char pkey[OQS_KEM_frodokem_1344_aes_length_public_key];
	// Lock memory where keys will be held
	if ((sodium_mlock(skey, OQS_KEM_frodokem_1344_aes_length_secret_key) != 0) ||
	    (sodium_mlock(pkey, OQS_KEM_frodokem_1344_aes_length_public_key) != 0)) {
		fputs("Error! unable to lock key memory! (key_pair_quantum)\n",
		      stderr);
	}
	puts("before here");
	OQS_KEM_frodokem_1344_aes_keypair(pkey, skey);
	puts("here");
	// Format the key lengths into network byte order
	unsigned char skey_len[2];
	unsigned char pkey_len[2];
	*((unsigned short *)skey_len) = htons(OQS_KEM_frodokem_1344_aes_length_secret_key);
	*((unsigned short *)pkey_len) = htons(OQS_KEM_frodokem_1344_aes_length_public_key);
	// Append the lengths to the key files.
	fwrite(skey_len, 2, 1, skey_file);
	fwrite(pkey_len, 2, 1, pkey_file);
	// Write the keys to their respective files
	fwrite(skey, 1, OQS_KEM_frodokem_1344_aes_length_secret_key, skey_file);
	fwrite(pkey, 1, OQS_KEM_frodokem_1344_aes_length_public_key, pkey_file);
	// Unlock the memory held by the keys, and zero out
	sodium_munlock(skey, OQS_KEM_frodokem_1344_aes_length_secret_key);
	sodium_munlock(pkey, OQS_KEM_frodokem_1344_aes_length_public_key);
	return 1;
}

// Generate a classical key exchange keypair using libsodium
// and store in the destination file.
static unsigned char key_file_generate_classical_keypair(FILE *pkey_file,
							 FILE *skey_file)
{
	// Generate classical keypair
	unsigned char cl_skey[crypto_kx_SECRETKEYBYTES];
	unsigned char cl_pkey[crypto_kx_PUBLICKEYBYTES];
	// Lock memory where keys will be held
	if ((sodium_mlock(cl_skey, crypto_kx_SECRETKEYBYTES) != 0) ||
	    (sodium_mlock(cl_pkey, crypto_kx_PUBLICKEYBYTES) != 0)) {
		fputs("Error! unable to lock key memory! (key_pair_classic)\n",
		      stderr);
	}
	crypto_kx_keypair(cl_pkey, cl_skey);
	// Format the key lengths into network byte order
	unsigned char cl_skey_len[2];
	unsigned char cl_pkey_len[2];
	*((unsigned short *)cl_skey_len) = htons(crypto_kx_SECRETKEYBYTES);
	*((unsigned short *)cl_pkey_len) = htons(crypto_kx_PUBLICKEYBYTES);
	// Append the lengths to the key files
	fwrite(cl_skey_len, 2, 1, skey_file);
	fwrite(cl_pkey_len, 2, 1, pkey_file);
	// Write the keys to their respective files
	fwrite(cl_skey, 1, crypto_kx_SECRETKEYBYTES, skey_file);
	fwrite(cl_pkey, 1, crypto_kx_PUBLICKEYBYTES, pkey_file);
	// Unlock the memory held by the keys, and zero out
	sodium_munlock(cl_skey, crypto_kx_SECRETKEYBYTES);
	sodium_munlock(cl_pkey, crypto_kx_PUBLICKEYBYTES);
	return 1;
}

// Generate both types of keys, and store both in a hybrid file where
// both keys are stored in sequence (quantum first, and then classical)
static unsigned char key_file_generate_hybrid_keypair(FILE *pkey_file,
						      FILE *skey_file)
{
	unsigned char q_success =
		key_file_generate_quantum_keypair(pkey_file, skey_file);
	unsigned char c_success =
		key_file_generate_classical_keypair(pkey_file, skey_file);
	return (q_success && c_success);
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
	unsigned char success = 1;
	// Choose and generate.
	switch (type) {
	// Generate keypair, and check whether the result was success
	// or failure.
	case key_file_classical:
		success = (key_file_generate_classical_keypair(pkey_file,
							       skey_file)) &&
			  success;
		break;
	case key_file_quantum:
		success = (key_file_generate_quantum_keypair(pkey_file,
							     skey_file)) &&
			  success;
		break;
	case key_file_hybrid:
		success = (key_file_generate_hybrid_keypair(pkey_file,
							    skey_file)) &&
			  success;
		break;
	}
	// We are finished generating the key files, close them.
	fclose(pkey_file);
	fclose(skey_file);
	// Return the outcome
	return success;
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
int key_file_verify_length(const char *key_file_path, size_t correct_len)
{
	//make sure that the length of the key in key file is correct
	if (key_file_get_size(key_file_path) != correct_len) {
		fputs("Error. the length of the key in the key file is incorrect. Exiting.\n",
		      stderr);
		return 0;
	}
	return 1;
}
