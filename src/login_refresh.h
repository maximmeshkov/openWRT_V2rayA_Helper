#ifndef V2RAYA_HELPER_LOGIN_REFRESH_H
#define V2RAYA_HELPER_LOGIN_REFRESH_H

#include "helper.h"
#include "v2raya_api.h"
#include <signal.h>

struct login_refresh {
    const char *credentials_path;
    int64_t next_attempt;
};

int discover_with_login(const struct v2raya_api *api, const char *xray_config,
                        struct login_refresh *refresh, struct inventory *out,
                        const volatile sig_atomic_t *stopping, char *error, size_t len);

#endif
