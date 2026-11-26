#ifndef V2RAYA_HELPER_NODE_KEY_H
#define V2RAYA_HELPER_NODE_KEY_H

/* Keep the same identity when v2rayA renumbers servers. Source may contain
 * a private subscription URL. Only expose the resulting key. */
void node_key(char key[33], const char *type, const char *source,
              const char *name, const char *address, const char *net);

#endif
