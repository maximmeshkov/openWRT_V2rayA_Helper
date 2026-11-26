#define _GNU_SOURCE
#include "routing_validate.h"

#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { MAX_LITERAL = 1024, VALIDATION_TIMEOUT_MS = 4500 };

static int regular_file(const char *path, int nonempty)
{
    struct stat info;
    return stat(path, &info) == 0 && S_ISREG(info.st_mode) && (!nonempty || info.st_size > 0);
}

static int64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
    return now.tv_sec * INT64_C(1000) + now.tv_nsec / 1000000;
}

static int wait_for_validation(pid_t child, int64_t deadline)
{
    for (;;) {
        int status;
        pid_t exited = waitpid(child, &status, WNOHANG);
        if (exited == child) return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (exited < 0 && errno != EINTR) return 0;
        int64_t now = monotonic_ms();
        if (now < 0 || now >= deadline) break;
        int64_t interval = deadline - now;
        struct timespec pause = {.tv_nsec = (interval < 20 ? interval : 20) * 1000000};
        nanosleep(&pause, NULL);
    }
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    return 0;
}

static void validate_child(pid_t parent, int input, const char *core_binary, char *asset_env)
{
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent)
        _exit(126);
    if (input == STDIN_FILENO) {
        if (fcntl(input, F_SETFD, 0) < 0) _exit(126);
    } else {
        if (dup2(input, STDIN_FILENO) < 0) _exit(126);
        close(input);
    }
    int output = open("/dev/null", O_WRONLY);
    if (output < 0 || dup2(output, STDOUT_FILENO) < 0 || dup2(output, STDERR_FILENO) < 0)
        _exit(126);
    if (output > STDERR_FILENO) close(output);
    char *const argv[] = {(char *)core_binary, "run", "-test", "-c", "stdin:", NULL};
    /* Do not import XRAY_LOCATION_CONFDIR or other runtime settings. */
    char *const envp[] = {asset_env, NULL};
    execve(core_binary, argv, envp);
    _exit(126);
}

int xray_validate_config(const char *core_binary, const char *assets_dir,
                         int input, unsigned int timeout_ms)
{
    if (!core_binary || core_binary[0] != '/' || !assets_dir || assets_dir[0] != '/' ||
        !regular_file(core_binary, 0)) return 0;

    char env[sizeof("XRAY_LOCATION_ASSET=") + PATH_MAX];
    int env_len = snprintf(env, sizeof(env), "XRAY_LOCATION_ASSET=%s", assets_dir);
    int64_t now = monotonic_ms();
    if (env_len < 0 || (size_t)env_len >= sizeof(env) || now < 0) return 0;

    pid_t parent = getpid();
    pid_t child = fork();
    if (child == 0) validate_child(parent, input, core_binary, env);
    return child > 0 && wait_for_validation(child, now + timeout_ms);
}

int routing_validate_advanced(const char *kind, const char *value,
                              const char *core_binary, const char *assets_dir)
{
    if (!kind || !value || !*value || strnlen(value, MAX_LITERAL + 1) > MAX_LITERAL ||
        !core_binary || core_binary[0] != '/' || !assets_dir || assets_dir[0] != '/' ||
        !regular_file(core_binary, 0)) return 0;

    const char *field = "domain", *asset = NULL;
    if (!strcmp(kind, "geosite")) {
        asset = "geosite.dat";
    } else if (!strcmp(kind, "geoip")) {
        field = "ip";
        asset = "geoip.dat";
    } else if (strcmp(kind, "regexp")) {
        return 0;
    }
    if (asset) {
        char path[PATH_MAX];
        int len = snprintf(path, sizeof(path), "%s/%s", assets_dir, asset);
        /* Xray can fall back to a system directory. Use the selected files. */
        if (len < 0 || (size_t)len >= sizeof(path) || !regular_file(path, 1)) return 0;
    }

    char spec[MAX_LITERAL + sizeof("geosite:")];
    snprintf(spec, sizeof(spec), "%s:%s", kind, value);
    json_object *literal = json_object_new_string(spec);
    if (!literal) return 0;
    const char *encoded = json_object_to_json_string_ext(literal, JSON_C_TO_STRING_PLAIN);
    char config[PIPE_BUF];
    int len = encoded ? snprintf(config, sizeof(config),
        "{\"log\":{\"loglevel\":\"none\"},\"outbounds\":[{\"protocol\":\"blackhole\",\"tag\":\"validate\"}],"
        "\"routing\":{\"rules\":[{\"type\":\"field\",\"outboundTag\":\"validate\",\"%s\":[%s]}]}}",
        field, encoded) : -1;
    json_object_put(literal);
    if (len < 0 || (size_t)len >= sizeof(config)) return 0;

    /* Preload one bounded write into an empty pipe before launching the child. */
    int channel[2];
    if (pipe2(channel, O_CLOEXEC | O_NONBLOCK) < 0) return 0;
    ssize_t written;
    do { written = write(channel[1], config, (size_t)len); } while (written < 0 && errno == EINTR);
    close(channel[1]);
    int valid = written == len &&
                xray_validate_config(core_binary, assets_dir, channel[0], VALIDATION_TIMEOUT_MS);
    close(channel[0]);
    return valid;
}
