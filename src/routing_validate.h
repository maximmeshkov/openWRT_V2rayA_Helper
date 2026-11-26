#ifndef V2RAYA_HELPER_ROUTING_VALIDATE_H
#define V2RAYA_HELPER_ROUTING_VALIDATE_H

/* Validate a regexp, geosite or geoip match with the selected Xray binary.
 * Both paths must be absolute. The caller selects the installed binary and
 * effective asset directory, independently of the user's rule input. */
int routing_validate_advanced(const char *kind, const char *value,
                              const char *core_binary, const char *assets_dir);

#endif
