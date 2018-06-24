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

    //length in bytes of the input to encrypt
    size_t in_buffer_length;

    //end of file
    int eof;

    //tag to specify what to do with the specific message being processed
    unsigned char tag;
