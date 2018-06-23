#include <stdio.h>
#include <sodium.h>

#define CHUNK_SIZE 4096

int main() {
    return 0;
}

long get_file_size(char* file_name) {
    long size;
    FILE *file;

    file = fopen(file_name, "rb");
    
    if (file == NULL) {
        fprintf(stderr, "Error. Unable to determine the size of %s. File pointer is NULL.\n", file_name);
        return -1;
    }

    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fclose(file);

    return size;
}

int encrypt_file(char* target_file, char* source_file, char* key_file_path) {

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

    //length in bytes of the input to encrypt
    size_t in_buffer_length;

    //end of file
    int eof;

    //tag to specify what to do with the specific message being processed
    unsigned char tag;

    //read the URIs to the source, target, and key file
    file_in = fopen(source_file, "rb");
    file_out = fopen(target_file, "wb");
    key_file = fopen(key_file_path, "rb");

    if ((file_in == NULL) || (file_out == NULL) || (key_file == NULL)) {
        fprintf(stderr, "Error. Either the input file, or key file doesn't exist at the location speficied. Exiting.\n");
        return -1;
    }

    //make sure that the length of the key in key file is correct
    if (get_file_size(key_file_path) != crypto_secretstream_xchacha20poly1305_KEYBYTES) {
        fprintf(stderr, "Error. the length of the key in the key file is incorrect. Exiting.\n");
        return -1;
    }

    //read the key in the key file into the key byte array, and close the file
    fread(encryption_key, 1, crypto_secretstream_xchacha20poly1305_KEYBYTES, key_file);
    fclose(key_file);

    //initiate the state and store the stream header into header
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, encryption_key);

    //write the header to the start of the output file
    fwrite(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, file_out);


}