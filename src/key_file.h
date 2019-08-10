#ifndef KEY_FILE_H
#define KEY_FILE_H

// Generate a random key using the function provided by the libsodium library
// and store it in the file at the path passed.
void key_file_generate(const char* dest_file);
// verify that the file passed is the correct length to be a key for
// xchacha20poly1305 (256bit == 32bytes)
int key_file_verify_length(const char* key_file_path);

#endif
