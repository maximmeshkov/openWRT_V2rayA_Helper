#include "boot_id.h"
#include <stdio.h>
#include <string.h>

int boot_id_valid(const char *id)
{
    if (!id || strlen(id) != BOOT_ID_LENGTH) return 0;
    for (unsigned i = 0; i < BOOT_ID_LENGTH; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (id[i] != '-') return 0;
        } else if (!strchr("0123456789abcdef", id[i])) {
            return 0;
        }
    }
    return 1;
}

int boot_id_read(char id[BOOT_ID_LENGTH + 1])
{
    id[0] = '\0';
    FILE *boot = fopen("/proc/sys/kernel/random/boot_id", "re");
    if (!boot) return 0;
    char text[BOOT_ID_LENGTH + 2];
    int valid = fread(text, 1, sizeof(text), boot) == BOOT_ID_LENGTH + 1 &&
                text[BOOT_ID_LENGTH] == '\n' && !ferror(boot);
    fclose(boot);
    if (!valid) return 0;
    text[BOOT_ID_LENGTH] = '\0';
    if (!boot_id_valid(text)) return 0;
    memcpy(id, text, BOOT_ID_LENGTH + 1);
    return 1;
}
