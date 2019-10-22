#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include "file_sym_enc.h"
#include "key_file.h"
#include "key_derive.h"
#include "m_string.h"

#define CHUNK_SIZE 4096

// encrypt the source file with xchacha20poly1305 and store the ciphertext
// in the target file using the encryption key passed.
// The files passed are closed by this function.
// file_in cleartext
// file_out ciphertext
static int encrypt_key(
	FILE *const file_in, FILE *const file_out,
	const unsigned char
		encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
	//encryption state
	crypto_secretstream_xchacha20poly1305_state state;
	//small header at the start of the file required to be able to decrypt said file
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	//initiate the state and store the stream header into header
	crypto_secretstream_xchacha20poly1305_init_push(&state, header,
							encryption_key);
	//write the header to the start of the output file
	fwrite(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES,
	       file_out);
	//end of file
	int eof;
	//loop until the end of the file has been reached.
	do {
		//buffer to read in a chunk of the file to encrypt
		unsigned char in_buffer[CHUNK_SIZE];
		//length that is read from the file to encrypt each time in the loop
		//read in a piece of the file into the buffer, and record it's length
		size_t read_length = fread(in_buffer, 1, CHUNK_SIZE, file_in);
		//check if we have reached the end of the file yet
		eof = feof(file_in);
		//tag to specify what to do with the specific message being processed
		//if reached the end of the file, set tag to FINAL TAG, otherwise set it to 0
		unsigned char tag =
			eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL :
			      0;
		//buffer to write a chunk to the destination encrypted file
		unsigned char
			out_buffer[CHUNK_SIZE +
				   crypto_secretstream_xchacha20poly1305_ABYTES];
		//length of output buffer for writing to file
		unsigned long long out_buffer_length;
		//encrypt the current in_buffer piece of the file, and store it in the
		//out_buffer to be written to the out file
		crypto_secretstream_xchacha20poly1305_push(
			&state, out_buffer, &out_buffer_length, in_buffer,
			read_length, NULL, 0, tag);
		//write the encrypted buffer to the resultant out file
		fwrite(out_buffer, 1, (size_t)out_buffer_length, file_out);
	} while (!eof);
	//close the remaining open files.
	fclose(file_in);
	fclose(file_out);
	return 0;
}

// clean up any loose ends after running a file decryption.
static int decrypt_cleanup(FILE *const file_in, FILE *const file_out,
			   int ret_value)
{
	fclose(file_in);
	if (file_out != NULL) {
		fclose(file_out);
	}
	return ret_value;
}

// decrypt the source file using the encryption key passed and store the plaintext
// in the target file. The files passed are closed by this function.
// file_in ciphertext
// file_out cleartext
static int decrypt_key(
	FILE *const file_in, FILE *const file_out,
	const unsigned char
		encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
	//small header at the start of the file required to be able to decrypt said file
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	//read the header information from the encrypted file into the header
	fread(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES,
	      file_in);
	//encryption state
	crypto_secretstream_xchacha20poly1305_state state;
	if (crypto_secretstream_xchacha20poly1305_init_pull(
		    &state, header, encryption_key) != 0) {
		fputs("Error. Incomplete header in file to decrypt. Exiting.\n",
		      stderr);
		return decrypt_cleanup(file_in, NULL, -1);
	}
	//end of file
	int eof;
	do {
		//buffer to read in a chunk of the file to decrypt
		unsigned char
			in_buffer[CHUNK_SIZE +
				  crypto_secretstream_xchacha20poly1305_ABYTES];
		//length that is read from the encrypted file each time in the loop
		//read piece of file to decrypt from the source file
		size_t read_length = fread(
			in_buffer, 1,
			CHUNK_SIZE +
				crypto_secretstream_xchacha20poly1305_ABYTES,
			file_in);
		//determine whether we are at the end of the file
		eof = feof(file_in);
		//buffer to write a chunk to the destination decrypted file
		unsigned char out_buffer[CHUNK_SIZE];
		//length of output buffer for writing to file
		unsigned long long out_buffer_length;
		//tag to specify what to do with the specific message being processed
		unsigned char tag;
		//make sure that the piece of the file we are decrypting
		//is not corrupted
		if (crypto_secretstream_xchacha20poly1305_pull(
			    &state, out_buffer, &out_buffer_length, &tag,
			    in_buffer, read_length, NULL, 0) != 0) {
			fputs("Error. Attempted to decrypt corrupted file chunk, "
			      "or encryption key is incorrect. Exiting.\n",
			      stderr);
			return decrypt_cleanup(file_in, file_out, -1);
		}
		//make sure that file end isn't reached before the end of the stream
		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL &&
		    !eof) {
			fputs("Error. end of file reached before end of the stream. Exiting.\n",
			      stderr);
			return decrypt_cleanup(file_in, file_out, -1);
		}
		fwrite(out_buffer, 1, (size_t)out_buffer_length, file_out);
		//loop until the end of the file has been reached.
	} while (!eof);
	//return success
	return decrypt_cleanup(file_in, file_out, 0);
}

// if password is NULL, retrieve the key using the path specified,
// and execute the callback operation
// with the key pulled from the file (encrypt or decrypt)
// otherwise, pull the salt out of the start of the source file (if decrypting)
// and insert the salt at the start of the target file if encrypting.
static int call_file_crypto(
	const char *const source_file, const char *const target_file,
	const char *const key_file_path, const char *const password,
	int (*operation)(
		FILE *const file_in, FILE *const file_out,
		const unsigned char encryption_key
			[crypto_secretstream_xchacha20poly1305_KEYBYTES]))
{
	unsigned char
		encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	// lock the memory that the encryption key is stored in, to avoid it being swapped to disk
	if (sodium_mlock(encryption_key,
			 crypto_secretstream_xchacha20poly1305_KEYBYTES) != 0) {
		fputs("Error! unable to lock key memory! (file_sym_enc)\n",
		      stderr);
		return -1;
	}
	// Open the source file to encrypt, and the target file
	// in which to store the ciphertext.
	FILE *const file_in = fopen(source_file, "rb");
	FILE *const file_out = fopen(target_file, "wb");
	if (file_in == NULL) {
		fputs("Error. The file to encrypt is NULL (file_sym_enc)\n",
		      stderr);
		return -1;
	}
	// Check if we need to deal with key derivation,
	// otherwise working with key files.
	// If a file is encrypted with a password it is
	// crucial that this step is executed as the salt is stored
	// at the start of the encrypted file; otherwise decryption
	// will fail because the stream header will have the salt
	// in it.
	if (password) {
		// Key derivation salt
		unsigned char salt[crypto_pwhash_SALTBYTES];
		if (operation == encrypt_key) {
			// Encrypting a file
			// Generate a new random salt
			randombytes_buf(salt, crypto_pwhash_SALTBYTES);
			// Write the salt to the start of the file.
			fwrite(salt, 1, crypto_pwhash_SALTBYTES, file_out);
		} else if (operation == decrypt_key) {
			// Decrypting a file
			// Read in the salt from the file
			fread(salt, 1, crypto_pwhash_SALTBYTES, file_in);
		}
		// Derive the encryption key from the salt.
		key_derive_sym_from_pass(password, salt, encryption_key);
	} else if (key_file_path) {
		// retrieve the encryption key from the file passed, and verify that the key file
		// contains a key of the right length. key_file_get_sym_key will write to stderr
		// on error, which is why no error is reported here.
		if (!key_file_get_sym_key(key_file_path, encryption_key))
			return -1;
	} else {
		fputs("Error. Neither a password, or a key file path was passed. "
		      "Halting. (file_sym_enc)\n",
		      stderr);
		return -1;
	}
	// operate on the file with the key extracted.
	int success = operation(file_in, file_out, encryption_key);
	// overwrite and unlock the encryption_key
	sodium_munlock(encryption_key,
		       crypto_secretstream_xchacha20poly1305_KEYBYTES);
	return success;
}

// dummy function that calls file_crypto with the goal to encrypt the source file
// using a key file and store the ciphertext in the target file.
int file_sym_enc_encrypt_key_file(const char *const source_file,
				  const char *const target_file,
				  const char *const key_file_path)
{
	return call_file_crypto(source_file, target_file, key_file_path, NULL,
				encrypt_key);
}

// dummy function that calls file_crypto with the goal to encrypt the source file
// using a password and store the ciphertext in the target file.
int file_sym_enc_encrypt_key_password(const char *const source_file,
				      const char *const target_file)
{
	struct m_string password = m_string_request_password();
	return call_file_crypto(source_file, target_file, NULL, password.arr,
				encrypt_key);
	// Unlock the password's memory and free it.
	sodium_munlock(password.arr, password.len);
	free(password.arr);
}

// dummy function to call file_crypto with the operation of decrypting the source
// file using a key file and putting the plaintext into the target file.
int file_sym_enc_decrypt_key_file(const char *const source_file,
				  const char *const target_file,
				  const char *const key_file_path)
{
	return call_file_crypto(source_file, target_file, key_file_path, NULL,
				decrypt_key);
}

// dummy function to call file_crypto with the operation of decrypting the source
// file using a password and putting the plaintext into the target file.
int file_sym_enc_decrypt_key_password(const char *const source_file,
				      const char *const target_file)
{
	struct m_string password = m_string_request_password();
	return call_file_crypto(source_file, target_file, NULL, password.arr,
				decrypt_key);
	// Unlock the password's memory and free it.
	sodium_munlock(password.arr, password.len);
	free(password.arr);
}
