#include <stdio.h>
#include <stdlib.h>
#include "m_string_get_string.h"

// result must be freed.
// Cannot return NULL string. Will exit first.
struct m_string m_string_get_string(void)
{
	char *string = NULL;
	size_t current_chunk_count = 1;
	char char_buf;
	// Read a string in from stdin, one character at a time.
	while ((char_buf = getchar()) != '\n') {
		// Allocate space for the new character in the string
		// being constructed.
		string = realloc(string, current_chunk_count);
		// Make sure string reallocation was successful.
		if (string == NULL) {
			fputs("Error. System out of memory.\n", stderr);
			exit(1);
		}
		// Append the newly read character to the string.
		string[current_chunk_count - 1] = char_buf;
		// Increase the count of added characters by 1.
		current_chunk_count++;
	}
	// Allocate space for the string's null terminator.
	string = realloc(string, current_chunk_count);
	// Set the null terminator at the end of the string.
	string[current_chunk_count - 1] = '\0';
	struct m_string string_built = { string, current_chunk_count };
	return string_built;
}
