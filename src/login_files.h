#ifndef V2RAYA_HELPER_LOGIN_FILES_H
#define V2RAYA_HELPER_LOGIN_FILES_H

struct login_credentials {
    char username[256];
    char password[256];
};

/* Return 0 on success. */
int login_credentials_read(const char *path, struct login_credentials *out);
void login_credentials_clear(struct login_credentials *out);
/* Check both paths before using credentials. A missing token target is valid. */
int login_files_distinct(const char *credentials, const char *token);
int login_token_replace(const char *path, const char *token);

#endif
