#ifndef KEY_DERIVE_H
#define KEY_DERIVE_H
// Derive a key for symmetric file encrytion using a randomly generated salt
// and the password passed.
// salt's length is crypto_pwhash_SALTBYTES
// key's length is crypto_secretstream_xchacha20poly1305_KEYBYTES
unsigned char key_derive_sym_from_pass(
	const char *const password, const unsigned char *const salt,
	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);
#endif
