#ifndef M_STRING_GET_STRING_H
#define M_STRING_GET_STRING_H
// String structure
struct m_string {
	char *arr;
	size_t len;
};
// result must be freed.
// Cannot return NULL string. Will exit first.
struct m_string m_string_get_string(void);
#endif
