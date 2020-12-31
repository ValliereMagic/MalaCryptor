#ifndef MALA_CRYPTOR_TESTS_H
#define MALA_CRYPTOR_TESTS_H
#include <check.h>

// THIS IS A HACK FOR VSCODIUM LINTING ONLY.
#ifndef TESTING
#include "mala_cryptor.c"
#endif
// THIS IS A HACK FOR VSCODIUM LINTING ONLY.

// Tests for mala_cryptor.c itself
START_TEST(mc_test_is_opt)
{
	// Make sure that finding a valid option with
	// enough arguments behind it is valid
	ck_assert(is_opt("-option", "-option", 1));
	// Make sure that finding an invalid option results
	// in 1
	ck_assert(!(is_opt("-option", "-not_the_same_option", 1)));
	// Make sure that not having the required amount of arguments
	// also results in 0
	ck_assert(!(is_opt("-option", "-option", 0)));
}
END_TEST

START_TEST(mc_test_check_optarg_val)
{
	// Make sure that invalid values return 0
	ck_assert(!(check_optarg_val("-tomato_soup")));
	// Make sure that valid values return 1
	ck_assert(check_optarg_val("./tomato_soup"));
}
END_TEST

char *test_callback_for_vals_call(char *test_string)
{
	// If this function returns "prev" it was not called
	// by the argument parser, or it was reset with the
	// sentinal string value.
	static char *called = "uncalled";
	puts(test_string);
	// Make a temp to return the previous value
	// of called instead of the one to set (test_string)
	char *called_value = called;
	called = test_string;
	return called_value;
}

START_TEST(mc_test_parse_args_vals_call)
{
	// Make a sample parsable argument for testing
	// this function
	struct parsable_argument p_a = {
		.num_vals = 1,
		.arg_key = "-tomato",
		.callback = (void (*)())test_callback_for_vals_call,
		.keypair = 0,
		.keypair_type = (enum keypair_type)0
	};
	// Dummy arguments list
	// valid argument and option list
	const char *const good_args_good_val[] = { "-tomato", "called" };
	// invalid ones
	const char *const good_args_no_val[] = { "-tomato" };
	const char *const bad_args_dont_match[] = { "-onion", "called" };
	const char *const bad_args_bad_val[] = { "-tomato", "-cucumber" };
	// Test whether it works correctly on a good argument with value
	int index = 0;
	ck_assert(parse_args_vals_call(&p_a, good_args_good_val, &index, 2) ==
		  1);
	// Make sure the callback was passed and executed
	// By checking that the value of the argument was passed to the test
	// function callback.
	ck_assert_str_eq(test_callback_for_vals_call("uncalled"),
			 good_args_good_val[1]);
	// Reset the index.
	// (index is modified to jump ahead over the values of an argument
	// for efficiency.)
	index = 0;
	// Make sure that calling with an argument that doesn't match the
	// arg_key in parsable argument results in 0, not a complete failure
	// as other arguments in the string could be executed, but this one
	// cannot be executed.
	ck_assert(parse_args_vals_call(&p_a, good_args_no_val, &index, 1) == 0);
	// Make sure that the test_callback wasn't called (still set to the
	// string uncalled)
	ck_assert_str_eq(test_callback_for_vals_call("uncalled"), "uncalled");
	// Don't need to reset the callback since we passed "uncalled" to it.
	// but need to reset index
	index = 0;
	// Make sure that calling a non-matching argument returns 0 as well
	// and doesn't execute a callback at all.
	ck_assert(parse_args_vals_call(&p_a, bad_args_dont_match, &index, 2) ==
		  0);
	// Make sure that the test_callback wasn't called (still set to the
	// string uncalled)
	ck_assert_str_eq(test_callback_for_vals_call("uncalled"), "uncalled");
	// Don't need to reset the callback since we passed "uncalled" to it.
	// but need to reset index
	index = 0;
	// test with a bad value to an argument (i.e a missed value, and the
	// start of another argument)
	ck_assert(parse_args_vals_call(&p_a, bad_args_bad_val, &index, 2) ==
		  -1);
	// Make sure that the test_callback wasn't called (still set to the
	// string uncalled)
	ck_assert_str_eq(test_callback_for_vals_call("uncalled"), "uncalled");
}
END_TEST

START_TEST(mc_test_parse_ops_exec)
{
	// TODO:
	// Test each of the program operations...
	// with filenames in the 'tests' dir
	// then fork and exec a bash cleanup script
	// to delete all of the files generated from running
	// this test.
}
END_TEST
// End tests for mala_cryptor.c

Suite *malacryptor_test_suite(void)
{
	Suite *malacryptor_tests = suite_create("MalaCryptor Test Suite");
	TCase *test_cases = tcase_create("mala_cryptor.c test cases");
	// Add tests to the test case
	tcase_add_test(test_cases, mc_test_is_opt);
	tcase_add_test(test_cases, mc_test_check_optarg_val);
	tcase_add_test(test_cases, mc_test_parse_args_vals_call);
	tcase_add_test(test_cases, mc_test_parse_ops_exec);
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
#endif
