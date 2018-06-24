#include <stdio.h>
#include <sodium.h>

#define CHUNK_SIZE 4096

int main() {
    return 0;
}

long get_file_size(char* file_name) {
    long size;
    FILE *file;

    //open the file in the mode to read bytes
    file = fopen(file_name, "rb");
    
    //make sure that the file exists.
    if (file == NULL) {
        fprintf(stderr, "Error. Unable to determine the size of %s. File pointer is NULL.\n", file_name);
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

int encrypt_file(char* target_file, char* source_file, char* key_file_path) {
    #include "define_vars.h"

    //read the URIs to the source, target, and key file
    file_in = fopen(source_file, "rb");
    file_out = fopen(target_file, "wb");
    key_file = fopen(key_file_path, "rb");

    if ((file_in == NULL) || (key_file == NULL)) {
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
    fwrite(header, 1, sizeof(header), file_out);


    do {
        //read in a piece of the file into the buffer, and record it's length
        in_buffer_length = fread(in_buffer, 1, sizeof(in_buffer), file_in);
        
        //check if we have reached the end of the file yet
        eof = feof(file_in);
        
        //if reached the end of the file, set tag to FINAL TAG, otherwise set it to 0
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;

        //encrypt the current in_buffer piece of the file, and store it in the out_buffer to be written to the
        //out file
        crypto_secretstream_xchacha20poly1305_push(&state, out_buffer, &out_buffer_length, in_buffer, in_buffer_length,
                                                   NULL, 0, tag);

        //write the encrypted buffer to the resultant out file
        fwrite(out_buffer, 1, (size_t) out_buffer_length, file_out);

    //loop until the end of the file has been reached.
    } while (!eof);

    //close the remaining open files.
    fclose(file_in);
    fclose(file_out);
    
    return 0;
}

int decrypt_file(char* target_file, char* source_file, char* key_file_path) {
    return 0;
}