#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include "m_string.h"
#ifdef _WIN32
#include <windows.h>
// Toggling terminal echo on windows platform
static int toggle_echo(unsigned char on_off)
{
	// Get a handle to the standard in file
	HANDLE handle_stdin = GetStdHandle(STD_INPUT_HANDLE);
	// Make sure we were successfully able to do so.
	if (handle_stdin == INVALID_HANDLE_VALUE) {
		fputs("Error. Unable to get a handle for stdin.\n", stderr);
		return 0;
	}
	// The mode we are going to change to either ON or OFF
	DWORD mode = 0;
	// Retrieve the current mode of the terminal
	int err = GetConsoleMode(handle_stdin, &mode);
	// Make sure we were able to get the terminal's current mode.
	if (err == 0) {
		fputs("Error. Unable to get terminal info.\n", stderr);
		return 0;
	}
	// Complete the operation specified by the function parameter.
	if (on_off)
		// set terminal echo mode to ON
		mode = mode | (ENABLE_ECHO_INPUT);
	else
		// OFF
		mode = mode & ~((DWORD)ENABLE_ECHO_INPUT);
	err = SetConsoleMode(handle_stdin, mode);
	// Make sure we were able to apply the changes that have been made.
	if (err == 0) {
		fputs("Error. Unable to set terminal info to updated mode.\n",
		      stderr);
		return 0;
	}
	// successful.
	return 1;
}
#else
#include <termios.h>
// Toggling echo on POSIX platform
static int toggle_echo(unsigned char on_off)
{
	struct termios terminal_info;
	// Get the current attributes of the terminal
	int err = tcgetattr(STDIN_FILENO, &terminal_info);
	// Make sure we were able to get them successfully.
	if (err != 0) {
		fputs("Error. Unable to get terminal info.\n", stderr);
		return 0;
	}
	// Set the attribute depending on the function parameter
	// passed.
	if (on_off)
		terminal_info.c_lflag |= ECHO;
	else
		terminal_info.c_lflag &= ~((tcflag_t)ECHO);
	// Apply the set attribute to the terminal.
	err = tcsetattr(STDIN_FILENO, TCSANOW, &terminal_info);
	// Make sure we were able to set the attribute successfully.
	if (err != 0) {
		fputs("Error. Unable to set terminal info to updated mode.\n",
		      stderr);
		return 0;
	}
	// successful.
	return 1;
}
#endif

// result must be freed.
// Cannot return NULL string. Will exit first.
struct m_string m_string_readline(void)
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

// returned password must be freed.
// return password must be sodium_munlocked
// Will not return a NULL result. Will exit first.
struct m_string m_string_request_password(void)
{
	// before asking the user for a password, turn off terminal echo...
	toggle_echo(0);
	unsigned char match;
	struct m_string password;
	do {
		// Set condition to exit loop if user enters identical passwords.
		match = 1;
		fputs("Enter a password: ", stdout);
		// Retrieve password from stdin.
		password = m_string_readline();
		// Move to the next line.
		fputs("\n", stdout);
		// Lock the password's memory from being swapped.
		sodium_mlock(password.arr, password.len);
		fputs("Enter it again: ", stdout);
		// Pull in a duplicate to compare to the password.
		struct m_string duplicate = m_string_readline();
		// Move to the next line.
		fputs("\n", stdout);
		// Lock the duplicate's memory from being swapped.
		sodium_mlock(duplicate.arr, duplicate.len);
		// Check whether the password and the duplicate
		// are the same.
		if (strcmp(password.arr, duplicate.arr) != 0) {
			match = 0;
			// Unlock the password's memory and free it.
			sodium_munlock(password.arr, password.len);
			free(password.arr);
		}
		// Unlock the duplicate's memory and free it.
		sodium_munlock(duplicate.arr, duplicate.len);
		free(duplicate.arr);
	} while (match == 0);
	// Turn terminal echo back on
	toggle_echo(1);
	return password;
}
