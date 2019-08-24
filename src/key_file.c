#include <sodium.h>
#include "key_file.h"
#ifdef _WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif
#include "api_frodo1344.h"

// Generate a random key using the function provided by the libsodium library
// and store it in the file at the path passed.
unsigned char key_file_generate_sym(const char *dest_file)
{
	// Make sure our destination file is valid.
	if (dest_file == NULL) {
		return 0;
	}
	unsigned char
		encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
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
	//print out length (in bytes) of the key written to file.
	printf("%d bytes written to key file.\n", (int)bytes_written);
	//close key file
	fclose(key_file_new);
	return 1;
}

unsigned char key_file_generate_hybrid_keypair(const char *dest_pkey_file,
					       const char *dest_skey_file)
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
	// Generate Quantum Resistant KEM keypair
	unsigned char skey[CRYPTO_SECRETKEYBYTES];
	unsigned char pkey[CRYPTO_PUBLICKEYBYTES];
	crypto_kem_keypair_Frodo1344(pkey, skey);
	// Format the key lengths into network byte order
	unsigned char skey_len[2];
	unsigned char pkey_len[2];
	*((unsigned short *)skey_len) = htons(CRYPTO_SECRETKEYBYTES);
	*((unsigned short *)pkey_len) = htons(CRYPTO_PUBLICKEYBYTES);
	// Append the lengths to the key files.
	fwrite(skey_len, 2, 1, skey_file);
	fwrite(pkey_len, 2, 1, pkey_file);
	// Write the keys to their respective files
	fwrite(skey, 1, CRYPTO_SECRETKEYBYTES, skey_file);
	fwrite(pkey, 1, CRYPTO_PUBLICKEYBYTES, pkey_file);
	// Generate classical keypair
	unsigned char cl_skey[crypto_box_SECRETKEYBYTES];
	unsigned char cl_pkey[crypto_box_PUBLICKEYBYTES];
	crypto_box_keypair(cl_pkey, cl_skey);
	// Format the key lengths into network byte order
	unsigned char cl_skey_len[2];
	unsigned char cl_pkey_len[2];
	*((unsigned short *)cl_skey_len) = htons(crypto_box_SECRETKEYBYTES);
	*((unsigned short *)cl_pkey_len) = htons(crypto_box_PUBLICKEYBYTES);
	// Append the lengths to the key files
	fwrite(cl_skey_len, 2, 1, skey_file);
	fwrite(cl_pkey_len, 2, 1, pkey_file);
	// Write the keys to their respective files
	fwrite(cl_skey, 1, crypto_box_SECRETKEYBYTES, skey_file);
	fwrite(cl_pkey, 1, crypto_box_PUBLICKEYBYTES, pkey_file);
	// close the key files
	fclose(pkey_file);
	fclose(skey_file);
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
