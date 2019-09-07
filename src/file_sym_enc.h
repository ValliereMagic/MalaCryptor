#ifndef FILE_SYM_ENC_H
#define FILE_SYM_ENC_H
// pull the encryption key out of the key file at the path passed
// then call file_sym_enc_encrypt_key with the extracted key.
int file_sym_enc_encrypt_key_file(const char *const source_file,
				  const char *const target_file,
				  const char *const key_file_path);
// Encrypt the source_file using the password passed, and store the
// result in the target file.
int file_sym_enc_encrypt_key_password(const char *const source_file,
				      const char *const target_file,
				      const char *const password);
// pull the encryption key out of the key file at the path passed
// then call file_sym_enc_decrypt_key with the extracted key.
int file_sym_enc_decrypt_key_file(const char *const target_file,
				  const char *const source_file,
				  const char *const key_file_path);
// Decrypt the source_file using the password passed, and stote the
// result in the target file.
int file_sym_enc_decrypt_key_password(const char *const source_file,
				      const char *const target_file,
				      const char *const password);
#endif
