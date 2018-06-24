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
