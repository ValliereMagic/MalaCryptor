#include <sodium.h>
#include "key_file.h"

// Generate a random key using the function provided by the libsodium library
// and store it in the file at the path passed.
void key_file_generate(char* dest_file)
{
    unsigned char encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    FILE* key_file_new = fopen(dest_file, "wb");
    //generate new encryption key for operations
    crypto_secretstream_xchacha20poly1305_keygen(encryption_key);
    //store new encryption key into file
    size_t bytes_written = fwrite(encryption_key, 1,
        crypto_secretstream_xchacha20poly1305_KEYBYTES, key_file_new);
    //print out length (in bytes) of the key written to file.
    printf("%d bytes written to key file.\n", (int)bytes_written);
    //close key file
    fclose(key_file_new);
}

// Get the length of the file name passed in bytes.
static long key_file_get_size(char* file_name)
{
    long size;
    FILE *file;
    //open the file in the mode to read bytes
    file = fopen(file_name, "rb");
    //make sure that the file exists.
    if (file == NULL) {
        fprintf(stderr, "Error. Unable to determine the size of %s. "
            "File pointer is NULL.\n", file_name);
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
int key_file_verify_length(char* key_file_path)
{
    //make sure that the length of the key in key file is correct
    if (key_file_get_size(key_file_path) != crypto_secretstream_xchacha20poly1305_KEYBYTES) {
        fputs("Error. the length of the key in the key file is incorrect. Exiting.\n", stderr);
        return 0;
    }
    return 1;
}
