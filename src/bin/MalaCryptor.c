#include <stdio.h>
#include <sodium.h>
#include <getopt.h>

#define CHUNK_SIZE 4096


void generate_key(char* dest_file) {
    unsigned char encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    FILE* key_file_new = fopen(dest_file, "wb");

    //generate new encryption key for operations
    crypto_secretstream_xchacha20poly1305_keygen(encryption_key);

    //store new encryption key into file
    size_t bytes_written = fwrite(encryption_key, 1, crypto_secretstream_xchacha20poly1305_KEYBYTES, key_file_new);

    //print out length (in bytes) of the key written to file.
    printf("%d bytes written to key file.\n", (int)bytes_written);

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
    if (!validate_key_file_size(key_file_path)) {
        return -1;
    }

    //read the key in the key file into the key byte array, and close the file
    fread(encryption_key, 1, crypto_secretstream_xchacha20poly1305_KEYBYTES, key_file);
    fclose(key_file);

    //initiate the state and store the stream header into header
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, encryption_key);

    //write the header to the start of the output file
    fwrite(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, file_out);


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
    if (!validate_key_file_size(key_file_path)) {
        return -1;
    }

    //read the key in the key file into the key byte array, and close the file
    fread(encryption_key, 1, crypto_secretstream_xchacha20poly1305_KEYBYTES, key_file);
    fclose(key_file);


    //read the header information from the encrypted file into the header
    fread(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, file_in);

    if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, encryption_key) != 0) {
        fprintf(stderr, "Error. Incomplete header in file to decrypt. Exiting.\n");
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

void help(void) {
    printf("MalaCryptor Help:\n");
    printf("\tOptions:\n");
    printf("\t\t-g [file path], to generate a new key, and store it in the specified file.\n");
    printf("\t\t-e [sourcefile] -o [out file] -k [key file] to encrypt a file using a key file\n");
    printf("\t\t-d [sourcefile] -o [out file] -k [key file] to decrypt a file using a key file\n");
    printf("\t\t-h for help\n");
}

int main(int arg_count, char* arguments[]) {
    
    //if the user doesn't specify an argument, present the help screen.
    if (arg_count == 1) {
        help();
        return 0;
    }
    
    //Initiate libsodium.
    if (sodium_init() < 0) {
        fprintf(stderr, "Error. Unable to initiate libsodium. Exiting.\n");
        return 1;
    }
    
    //encrypt arguments
    char encrypt_flag = 0;
    char* encrypt_file_path = NULL;

    //decrypt arguments
    char decrypt_flag = 0;
    char* decrypt_file_path = NULL;

    //output file arguments
    char output_flag = 0;
    char* output_file_path = NULL;

    //key file arguments
    char key_file_flag = 0;
    char* key_file_path = NULL;
    
    //current argument to be parsed
    int current_arg;

    while ((current_arg = getopt(arg_count, arguments, "g:e:o:k:d:h")) != -1) {
        switch (current_arg) {
            case 'h': {
                help();
                return 0;
            }
            case 'g': {
                generate_key(optarg);
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
        
        int out_and_key_valid = ((output_flag) && (output_file_path != NULL) &&
                                (key_file_flag) && (key_file_path != NULL));
    
        //encrypt a file, if all the valid flags are set
        if (encrypt_flag) {
            if ((encrypt_file_path != NULL) &&
                out_and_key_valid) {
            
                if (encrypt_file(output_file_path, encrypt_file_path, key_file_path) != 0) {
                    fprintf(stderr, "An error occurred while encrypting the file.\n");
                    return 1;
                }
            } else {
                help();
            }
        
        //decrypt a file, if all the valid flags are set
        } else if (decrypt_flag) {
            if ((decrypt_flag) && (decrypt_file_path != NULL) &&
                out_and_key_valid) {
            
                if (decrypt_file(output_file_path, decrypt_file_path, key_file_path) != 0) {
                    fprintf(stderr, "An error occurred while decrypting the file.\n");
                    return 1;
                }
            } else {
                help();
            }
        }
    }

    return 0;
}
