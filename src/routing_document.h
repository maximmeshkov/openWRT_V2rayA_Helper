#ifndef V2RAYA_HELPER_ROUTING_DOCUMENT_H
#define V2RAYA_HELPER_ROUTING_DOCUMENT_H

#include <stddef.h>

/* On success, return NULL and assign a newly allocated string. Errors are
 * public identifiers containing no user input. The caller frees the string.
 * regexp, geosite and geoip require separate validation by the running
 * installation's Xray before saving. */
const char *routing_build_rule(const char *type, const char *value, const char *outbound,
                               char **rule);

/* before_line = 0 appends. Other values are one-based source line numbers. */
int routing_can_insert_before(const char *document, size_t before_line);
/* Fill at most capacity positions. The return value counts all suitable
 * lines so a caller can tell whether it showed a full or partial list. */
size_t routing_list_positions(const char *document, size_t *lines, size_t capacity);
const char *routing_insert_rule(const char *document, const char *rule, size_t before_line,
                                char **updated);

#endif
