#include <stdio.h>
#include <sodium.h>
#include "file_sym_enc.h"
#include "key_file.h"

#define CHUNK_SIZE 4096

// retrieve the encryption key stored at the path passed
// make sure that the key is the correct length for
// xchacha20
static int get_encryption_key(
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

// retrieve the key using the path specified, and execute the callback operation
// with the key pulled from the file (encrypt or decrypt)
static int call_file_crypto(
	const char *target_file, const char *source_file,
	const char *key_file_path,
	int (*operation)(
		const char *target_file, const char *source_file,
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
	// retrieve the encryption key from the file passed, and verify that the key file
	// contains a key of the right length.
	if (!get_encryption_key(key_file_path, encryption_key))
		return -1;
	// operate on the file with the key extracted.
	int success = operation(target_file, source_file, encryption_key);
	// overwrite and unlock the encryption_key
	sodium_munlock(encryption_key,
		       crypto_secretstream_xchacha20poly1305_KEYBYTES);
	return success;
}

// dummy function that calls file_crypto with the goal to encrypt the source file
// and store the ciphertext in the target file.
int file_sym_enc_encrypt_key_file(const char *target_file,
				  const char *source_file,
				  const char *key_file_path)
{
	return call_file_crypto(target_file, source_file, key_file_path,
				file_sym_enc_encrypt_key);
}

// encrypt the source file with xchacha20poly1305 and store the ciphertext
// in the target file using the encryption key passed.
int file_sym_enc_encrypt_key(
	const char *target_file, const char *source_file,
	const unsigned char
		encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
	//open the source file to encrypt for reading
	FILE *file_in = fopen(source_file, "rb");
	//make sure that the file being read from is not NULL
	if (file_in == NULL) {
		fputs("Error. the file to encrypt is NULL.\n", stderr);
		return -1;
	}
	//encryption state
	crypto_secretstream_xchacha20poly1305_state state;
	//small header at the start of the file required to be able to decrypt said file
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	//initiate the state and store the stream header into header
	crypto_secretstream_xchacha20poly1305_init_push(&state, header,
							encryption_key);
	// open the target file for writing
	FILE *file_out = fopen(target_file, "wb");
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

// dummy function to call file_crypto with the operation of decrypting the source
// file and putting the plaintext into the target file.
int file_sym_enc_decrypt_key_file(const char *target_file,
				  const char *source_file,
				  const char *key_file_path)
{
	return call_file_crypto(target_file, source_file, key_file_path,
				file_sym_enc_decrypt_key);
}

static inline int decrypt_return_status_cleanup(FILE *file_in, FILE *file_out,
						int ret_value)
{
	fclose(file_in);
	if (file_out != NULL) {
		fclose(file_out);
	}
	return ret_value;
}

// decrypt the source file using the encryption key passed and store the plaintext
// in the target file.
int file_sym_enc_decrypt_key(
	const char *target_file, const char *source_file,
	const unsigned char
		encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
	// file to decrypt.
	FILE *file_in = fopen(source_file, "rb");
	//make sure that the file being read from is not NULL
	if (file_in == NULL) {
		fputs("Error. the file to encrypt is NULL.\n", stderr);
		return -1;
	}
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
		return decrypt_return_status_cleanup(file_in, NULL, -1);
	}
	//end of file
	int eof;
	// file to write decrypted data to.
	FILE *file_out = fopen(target_file, "wb");
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
			fputs("Error. Attempted to decrypt corrupted file chunk. Exiting.\n",
			      stderr);
			return decrypt_return_status_cleanup(file_in, file_out,
							     -1);
		}
		//make sure that file end isn't reached before the end of the stream
		if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL &&
		    !eof) {
			fputs("Error. end of file reached before end of the stream. Exiting.\n",
			      stderr);
			return decrypt_return_status_cleanup(file_in, file_out,
							     -1);
		}
		fwrite(out_buffer, 1, (size_t)out_buffer_length, file_out);
		//loop until the end of the file has been reached.
	} while (!eof);
	//return success
	return decrypt_return_status_cleanup(file_in, file_out, 0);
}
