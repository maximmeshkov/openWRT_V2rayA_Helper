#ifndef V2RAYA_HELPER_BOOT_ID_H
#define V2RAYA_HELPER_BOOT_ID_H

enum { BOOT_ID_LENGTH = 36 };

int boot_id_valid(const char *id);
int boot_id_read(char id[BOOT_ID_LENGTH + 1]);

#endif
