#include "login_refresh.h"
#include "core_watch.h"
#include "login_files.h"
#include <stdio.h>
#include <stdlib.h>

static int refresh_token(const struct v2raya_api *api, const char *credentials_path,
                         const volatile sig_atomic_t *stopping, char *error, size_t len)
{
    if (login_files_distinct(credentials_path, api->token_file)) {
        snprintf(error, len, "v2rayA authorization renewal needs separate private login and token files");
        return -1;
    }
    /* POST /api/login takes {username, password} and returns data.token in both
     * v2rayA 2.2.7.4 and 2.5.16 (controller/login.go), and the new token is
     * checked with an authorized request before it replaces the old one, so
     * renewal needs no version gate. */
    struct login_credentials credentials = {0};
    if (login_credentials_read(credentials_path, &credentials)) {
        snprintf(error, len, "cannot read the private v2rayA authorization credentials");
        return -1;
    }
    struct core_watch_peer connection = {.api = api->base, .stopping = stopping};
    char *token = v2raya_api_login_token(api, credentials.username, credentials.password,
                                        core_watch_verify_peer, &connection, error, len);
    login_credentials_clear(&credentials);
    if (!token) return -1;

    int result = -1;
    if (!*stopping && !login_files_distinct(credentials_path, api->token_file))
        result = login_token_replace(api->token_file, token);
    free(token);
    if (result) snprintf(error, len, "cannot save the renewed v2rayA authorization token");
    return result;
}

int discover_with_login(const struct v2raya_api *api, const char *xray_config,
                        struct login_refresh *refresh, struct inventory *out,
                        const volatile sig_atomic_t *stopping, char *error, size_t len)
{
    int result = load_inventory(api, xray_config, out, error, len);
    if (result != INVENTORY_AUTH_REQUIRED || !refresh->credentials_path || *stopping) return result;

    int64_t now = probe_clock_ms();
    if (now < refresh->next_attempt) return result;
    refresh->next_attempt = now + 60000;
    char detail[160] = {0};
    if (refresh_token(api, refresh->credentials_path, stopping, detail, sizeof(detail))) {
        snprintf(error, len, "v2rayA authorization renewal failed%s%s",
                 *detail ? ": " : "", detail);
        return result;
    }
    error[0] = '\0';
    return load_inventory(api, xray_config, out, error, len);
}
