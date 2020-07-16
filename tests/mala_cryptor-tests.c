#include <check.h>
#include <stdio.h>
#include <sodium.h>
#include <string.h>
#include "file_sym_enc.h"
#include "key_derive.h"
#include "key_file.h"
#include "m_string.h"

START_TEST(malacryptor_test_keypair_operations)
{
	puts("~~Keypair Operation Tests~~");
}
END_TEST

START_TEST(malacryptor_test_symkey_operations)
{
	puts("~~Symmetric Key Encryption Tests~~");
}
END_TEST

START_TEST(malacryptor_test_key_derivation)
{
	puts("~~Key Derivation Tests~~");
}
END_TEST

START_TEST(malacryptor_test_mstring)
{
	puts("~~mstring Function Tests~~");
}
END_TEST

Suite *malacryptor_test_suite(void)
{
	Suite *malacryptor_tests = suite_create("MalaCryptor Test Suite");
	TCase *test_cases = tcase_create("MalaCryptor Test Casese");
	// Add tests to the test case
	tcase_add_test(test_cases, malacryptor_test_keypair_operations);
	tcase_add_test(test_cases, malacryptor_test_symkey_operations);
	tcase_add_test(test_cases, malacryptor_test_key_derivation);
	tcase_add_test(test_cases, malacryptor_test_mstring);
	// Add the test case to the suite
	suite_add_tcase(malacryptor_tests, test_cases);
	return malacryptor_tests;
}

int main(void)
{
	//Initiate libsodium.
	if (sodium_init() < 0) {
		fputs("Error. Unable to initiate libsodium. Exiting.\n",
		      stderr);
		return EXIT_FAILURE;
	}
	Suite *suite = malacryptor_test_suite();
	// Create the suite runner
	SRunner *suite_runner = srunner_create(suite);
	// Run all the tests in the suite
	srunner_run_all(suite_runner, CK_NORMAL);
	// Get the results so that we can calculate an exit
	// code that makes sense
	int number_of_failed_tests = srunner_ntests_failed(suite_runner);
	// free the suite runner
	srunner_free(suite_runner);
	// Return a status code that makes sense
	if (number_of_failed_tests == 0)
		return EXIT_SUCCESS;
	return EXIT_FAILURE;
}
