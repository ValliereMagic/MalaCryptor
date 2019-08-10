#ifndef FILE_SYM_ENC_H
#define FILE_SYM_ENC_H

int file_sym_enc_encrypt(char* target_file, char* source_file, char* key_file_path);
int file_sym_enc_decrypt(char* target_file, char* source_file, char* key_file_path);

#endif
