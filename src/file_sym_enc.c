#include <stdio.h>
#include <sodium.h>
#include "key_file.h"

#define CHUNK_SIZE 4096

static int validate_files(FILE* file_in, FILE* key_file)
{
    //make sure that the files being read from are not NULL
    if ((file_in == NULL) || (key_file == NULL)) {
        fputs("Error. Either the input file, or key file doesn't exist at the location speficied. Exiting.\n", stderr);
        return 0;
    }
    return 1;
}

int file_sym_enc_encrypt(char* target_file, char* source_file, char* key_file_path)
{
    //buffer to read in a chunk of the file to encrypt
    unsigned char in_buffer[CHUNK_SIZE];
    //buffer to write a chunk to the destination encrypted file
    unsigned char out_buffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    //where the key is going to be stored when it is read in
    unsigned char encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    //small header at the start of the file required to be able to decrypt said file
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    //encryption state
    crypto_secretstream_xchacha20poly1305_state state;
    //pointers for the input and output file
    FILE *file_in, *file_out, *key_file;
    //length of output buffer for writing to file
    unsigned long long out_buffer_length;
    //length that is read from the file to encrypt each time in the loop
    size_t read_length;
    //end of file
    int eof;
    //tag to specify what to do with the specific message being processed
    unsigned char tag;
    //read in the URIs to the source, target, and key file
    file_in = fopen(source_file, "rb");
    file_out = fopen(target_file, "wb");
    key_file = fopen(key_file_path, "rb");
    //make sure that the files being read from are not NULL
    if (!validate_files(file_in, key_file)) {
        return -1;
    }
    //make sure that the length of the key in key file is correct
    if (!key_file_verify_length(key_file_path)) {
        return -1;
    }
    //read the key in the key file into the key byte array, and close the file
    fread(encryption_key, 1, crypto_secretstream_xchacha20poly1305_KEYBYTES, key_file);
    fclose(key_file);
    //initiate the state and store the stream header into header
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, encryption_key);
    //write the header to the start of the output file
    fwrite(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, file_out);
    //loop until the end of the file has been reached.
    do {
        //read in a piece of the file into the buffer, and record it's length
        read_length = fread(in_buffer, 1, CHUNK_SIZE, file_in);
        //check if we have reached the end of the file yet
        eof = feof(file_in);
        //if reached the end of the file, set tag to FINAL TAG, otherwise set it to 0
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        //encrypt the current in_buffer piece of the file, and store it in the out_buffer to be written to the
        //out file
        crypto_secretstream_xchacha20poly1305_push(&state, out_buffer, &out_buffer_length, in_buffer, read_length,
                                                   NULL, 0, tag);
        //write the encrypted buffer to the resultant out file
        fwrite(out_buffer, 1, (size_t) out_buffer_length, file_out);
    } while (!eof);
    //close the remaining open files.
    fclose(file_in);
    fclose(file_out);
    return 0;
}

static int decrypt_return_status_cleanup(FILE* file_in, FILE* file_out, int* ret_value)
{
    fclose(file_in);
    fclose(file_out);
    return *ret_value;
}

int file_sym_enc_decrypt(char* target_file, char* source_file, char* key_file_path)
{
    //buffer to read in a chunk of the file to decrypt
    unsigned char in_buffer[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    //buffer to write a chunk to the destination decrypted file
    unsigned char out_buffer[CHUNK_SIZE];
    //where the key is going to be stored when it is read in
    unsigned char encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    //small header at the start of the file required to be able to decrypt said file
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    //encryption state
    crypto_secretstream_xchacha20poly1305_state state;
    //pointers for the input and output file
    FILE *file_in, *file_out, *key_file;
    //length of output buffer for writing to file
    unsigned long long out_buffer_length;
    //length that is read from the encrypted file each time in the loop
    size_t read_length;
    //end of file
    int eof;
    //tag to specify what to do with the specific message being processed
    unsigned char tag;
    int ret_value = -1;
    //read in the URIs to the source, target, and key file
    file_in = fopen(source_file, "rb");
    file_out = fopen(target_file, "wb");
    key_file = fopen(key_file_path, "rb");
    //make sure that the files being read from are not NULL
    if (!validate_files(file_in, key_file)) {
        return -1;
    }
    //make sure that the length of the key in key file is correct
    if (!key_file_verify_length(key_file_path)) {
        return -1;
    }
    //read the key in the key file into the key byte array, and close the file
    fread(encryption_key, 1, crypto_secretstream_xchacha20poly1305_KEYBYTES, key_file);
    fclose(key_file);
    //read the header information from the encrypted file into the header
    fread(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, file_in);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, encryption_key) != 0) {
        fputs("Error. Incomplete header in file to decrypt. Exiting.\n", stderr);
        return decrypt_return_status_cleanup(file_in, file_out, &ret_value);
    }
    do {
        //read piece of file to decrypt from the source file
        read_length = fread(in_buffer, 1,
                            CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES,
                            file_in);
        //determine whether we are at the end of the file
        eof = feof(file_in);
        //make sure that the piece of the file we are decrypting
        //is not corrupted
        if (crypto_secretstream_xchacha20poly1305_pull(&state, out_buffer,
                                                       &out_buffer_length,
                                                       &tag, in_buffer,
                                                       read_length,
                                                       NULL, 0) != 0) {
            fputs("Error. Attempted to decrypt corrupted file chunk. Exiting.\n", stderr);
            return decrypt_return_status_cleanup(file_in, file_out, &ret_value);
        }
        //make sure that file end isn't reached before the end of the stream
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            fputs("Error. end of file reached before end of the stream. Exiting.\n", stderr);
            return decrypt_return_status_cleanup(file_in, file_out, &ret_value);
        }
        fwrite(out_buffer, 1, (size_t) out_buffer_length, file_out);
    //loop until the end of the file has been reached.
    } while (!eof);
    //set and return success
    ret_value = 0;
    return decrypt_return_status_cleanup(file_in, file_out, &ret_value);
}
