#include <stdio.h>
#include <sodium.h>
#include <getopt.h>

#define CHUNK_SIZE 4096


int generate_key(char* dest_file) {
    unsigned char encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    FILE* key_file_new = fopen(dest_file, "wb");

    //generate new encryption key for operations
    crypto_secretstream_xchacha20poly1305_keygen(encryption_key);

    //store new encryption key into file
    fwrite(encryption_key, 1, sizeof(encryption_key, key_file_new));

    //close key file
    fclose(key_file_new);

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

int validate_key_file_size(char* key_file_path) {
    //make sure that the length of the key in key file is correct
    if (get_file_size(key_file_path) != crypto_secretstream_xchacha20poly1305_KEYBYTES) {
        fprintf(stderr, "Error. the length of the key in the key file is incorrect. Exiting.\n");
        return 0;
    }
    return 1;
}

int validate_files(FILE* file_in, FILE* key_file) {
    //make sure that the files being read from are not NULL
    if ((file_in == NULL) || (key_file == NULL)) {
        fprintf(stderr, "Error. Either the input file, or key file doesn't exist at the location speficied. Exiting.\n");
        return 0;
    }
    return 1;
}

int encrypt_file(char* target_file, char* source_file, char* key_file_path) {
    //include common variable definitions between encrypt and decrypt
    #include "define_vars.h"

    //include common file operations and reads between encrypt and decrypt
    #include "common_file_work.h"

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

int decrypt_return_status_cleanup(FILE* file_in, FILE* file_out, int* ret_value) {
    fclose(file_in);
    fclose(file_out);
    return *ret_value;
}

int decrypt_file(char* target_file, char* source_file, char* key_file_path) {
    //include common variable definitions between encrypt and decrypt
    #include "define_vars.h"

    int ret_value = -1;
    
    //include common file operations and reads between encrypt and decrypt
    #include "common_file_work.h"

    //read the header information from the encrypted file into the header
    fread(header, 1, sizeof(header), file_in);

    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, encryption_key) != 0) {
        fprintf(stderr, "Error. Incomplete header in file to decrypt. Exiting.\n");
        return decrypt_return_status_cleanup(file_in, file_out, &ret_value);
    }

    do {
        //read piece of file to encrypt from the source file
        in_buffer_length = fread(in_buffer, 1, sizeof(in_buffer), file_in);

        //determine whether we are at the end of the file
        eof = feof(file_in);

        //make sure that the piece of the file we are decrypting
        //is not corrupted
        if (crypto_secretstream_xchacha20poly1305_pull(&state, out_buffer,
                                                       &out_buffer_length,
                                                       &tag, in_buffer,
                                                       in_buffer_length,
                                                       NULL, 0) != 0) {
            
            fprintf(stderr, "Error. Attempted to decrypt corrupted file chunk. Exiting.\n");
            return decrypt_return_status_cleanup(file_in, file_out, &ret_value);
        }

        //make sure that file end isn't reached before the end of the stream
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            fprintf(stderr, "Error. end of file reached before end of the stream. Exiting.\n");
            return decrypt_return_status_cleanup(file_in, file_out, &ret_value);
        }
        fwrite(out_buffer, 1, (size_t) out_buffer_length, file_out);
    
    //loop until the end of the file has been reached.
    } while (!eof);
    
    //set and return success
    ret_value = 0;
    return decrypt_return_status_cleanup(file_in, file_out, &ret_value);
}

int main(int arg_count, char* arguments[]) {
    int encrypt_file_flag = 0;
    char* encrypt_file_URI = NULL;
    
    int decrypt_file_flag = 0;
    char* decrypt_file_URI = NULL;

    int help_flag = 0;

    
    return 0;
}
