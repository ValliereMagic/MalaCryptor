#include <sodium.h>
#include <string.h>
#include "key_derive.h"

// Derive a key for symmetric file encrytion using a randomly generated salt
// and the password passed.
unsigned char key_derive_sym_from_pass(
	const char *const password, const unsigned char *const salt,
	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
	// Derive the key using crypto_pwhash
	unsigned char success = crypto_pwhash(
		key, crypto_secretstream_xchacha20poly1305_KEYBYTES, password,
		strlen(password), salt, crypto_pwhash_OPSLIMIT_MODERATE,
		crypto_pwhash_MEMLIMIT_MODERATE, crypto_pwhash_ALG_DEFAULT);
	// Make sure we were able to successfully derive a key from the password
	// passed.
	if (success != 0) {
		fputs("Error. Unable to derive symmetric key from password in key_derive.\n",
		      stderr);
		return 0;
	}
	return 1;
}
