#ifndef FILE_SYM_ENC_H
#define FILE_SYM_ENC_H

// pull the encryption key out of the key file at the path passed
// then call file_sym_enc_encrypt_key with the extracted key.
int file_sym_enc_encrypt_key_file(const char* target_file, const char* source_file,
                                  const char* key_file_path);
// encrypt the source file with xchacha20poly1305 and store the ciphertext
// in the target file using the encryption key passed.
int file_sym_enc_encrypt_key(const char* target_file, const char* source_file,
                             const unsigned char encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
// pull the encryption key out of the key file at the path passed
// then call file_sym_enc_decrypt_key with the extracted key.
int file_sym_enc_decrypt_key_file(const char* target_file, const char* source_file,
                                  const char* key_file_path);
// decrypt the source file using the encryption key passed and store the plaintext
// in the target file.
int file_sym_enc_decrypt_key(const char* target_file, const char* source_file, 
                             const unsigned char encryption_key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

#endif
