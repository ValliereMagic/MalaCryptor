#ifndef KEY_FILE_H
#define KEY_FILE_H

enum keypair_type { key_file_classical, key_file_quantum, key_file_hybrid };
// Generate a keypair for sending a file to another person by sending the
// symmetric key using a key encapsulation mechanism
unsigned char key_file_generate_keypair(const char *dest_pkey_file,
					const char *dest_skey_file,
					enum keypair_type type);
// Generate a random key using the function provided by the
// libsodium library and store it in the file at the path passed.
unsigned char key_file_generate_sym(const char *dest_file);
// verify that the file passed is the correct length to be a key for
// xchacha20poly1305 (256bit == 32bytes)
int key_file_verify_length(const char *key_file_path, size_t correct_len);

#endif
