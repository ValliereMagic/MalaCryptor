#ifndef M_STRING
#define M_STRING
// String structure
struct m_string {
	char *arr;
	size_t len;
};
// result must be freed.
// Cannot return NULL string. Will exit first.
struct m_string m_string_readline(void);
// returned password must be freed.
// return password must be sodium_munlocked
// Will not return a NULL result. Will exit first.
struct m_string m_string_request_password(void);
#endif
