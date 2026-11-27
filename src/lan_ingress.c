#define _GNU_SOURCE
#include "lan_ingress.h"
#include "capability.h"
#include "core_watch.h"
#include "helper.h"
#include "lan_ingress_netlink.h"
#include "lan_tproxy_nft.h"
#include "lan_tproxy_route.h"
#include "node_key.h"
#include "node_profile.h"
#include "redirect_checkpoint.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

enum { RULESET_LIMIT = 256 * 1024, QUERY_TIMEOUT_MS = 1000 };
enum lan_mode { LAN_NONE, LAN_REDIRECT, LAN_TPROXY };

static int is_string(json_object *value, const char *expected)
{
    return json_object_is_type(value, json_type_string) &&
           !strcmp(json_object_get_string(value), expected);
}

static enum lan_mode stock_lan_mode(json_object *config)
{
    json_object *inbounds = json_object_object_get(config, "inbounds");
    if (!json_object_is_type(inbounds, json_type_array)) return LAN_NONE;
    enum lan_mode mode = LAN_NONE;
    unsigned tags = 0;
    for (size_t i = 0; i < json_object_array_length(inbounds); i++) {
        json_object *in = json_object_array_get_idx(inbounds, i);
        json_object *name = json_object_object_get(in, "tag");
        unsigned tag = is_string(name, "transparent") ? 1 : is_string(name, "transparent_ipv4") ? 2 :
                       is_string(name, "transparent_ipv6") ? 4 : 0;
        if (!tag) continue;
        json_object *port = json_object_object_get(in, "port");
        json_object *settings = json_object_object_get(in, "settings");
        json_object *stream = json_object_object_get(in, "streamSettings");
        json_object *sockopt = json_object_object_get(stream, "sockopt");
        json_object *follow = json_object_object_get(settings, "followRedirect");
        json_object *proxy = json_object_object_get(sockopt, "tproxy");
        enum lan_mode candidate = is_string(proxy, "tproxy") ? LAN_TPROXY :
                                  is_string(proxy, "redirect") && tag == 1 ? LAN_REDIRECT : LAN_NONE;
        if ((tags & tag) || (mode && mode != candidate) || !candidate ||
            !json_object_is_type(port, json_type_int) || json_object_get_int64(port) != 52345 ||
            !is_string(json_object_object_get(in, "protocol"), "dokodemo-door") ||
            !json_object_is_type(follow, json_type_boolean) || !json_object_get_boolean(follow))
            return LAN_NONE;
        tags |= tag;
        mode = candidate;
    }
    /* The stock template uses either one shared TPROXY inbound or the per-family inbounds. */
    return tags == 1 || tags == 2 || tags == 6 ? mode : LAN_NONE;
}

static int same_network(pid_t pid, const struct stat *self)
{
    struct stat other;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/ns/net", (long)pid);
    return !stat(path, &other) && self->st_dev == other.st_dev && self->st_ino == other.st_ino;
}

static int nftables_loaded(void)
{
    if (!access("/sys/module/nf_tables", F_OK)) return 1;
    /* Built-in Netfilter need not have a directory under /sys/module. */
    static int built_in = -1;
    if (built_in >= 0) return built_in;
    built_in = 0;
    FILE *symbols = fopen("/proc/kallsyms", "re");
    if (!symbols) return 0;
    char line[256];
    while (fgets(line, sizeof(line), symbols)) {
        if (strstr(line, " nf_tables_gettable\n")) {
            built_in = 1;
            break;
        }
    }
    fclose(symbols);
    return built_in;
}

static int read_rules(const char *path, char *const args[], char *output,
                      const volatile sig_atomic_t *stopping)
{
    if (*stopping || access(path, X_OK)) return 0;
    int channel[2];
    if (pipe2(channel, O_CLOEXEC)) return 0;
    pid_t parent = getpid(), child = fork();
    if (child == 0) {
        close(channel[0]);
        int null = open("/dev/null", O_RDWR | O_CLOEXEC);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent || null < 0 ||
            dup2(null, STDIN_FILENO) < 0 || dup2(null, STDERR_FILENO) < 0 ||
            dup2(channel[1], STDOUT_FILENO) < 0) _exit(1);
        char *const env[] = {"LC_ALL=C", NULL};
        execve(path, args, env);
        _exit(1);
    }
    close(channel[1]);
    int status, complete = 0;
    pid_t reaped = 0;
    size_t used = 0;
    int64_t deadline = probe_clock_ms() + QUERY_TIMEOUT_MS;
    while (child > 0 && !*stopping && used < RULESET_LIMIT) {
        int64_t left = deadline - probe_clock_ms();
        if (left <= 0) break;
        if (complete) {
            reaped = waitpid(child, &status, WNOHANG);
            if (reaped == child) break;
            if (reaped < 0 && errno != EINTR) break;
            if (!reaped) poll(NULL, 0, left < 5 ? (int)left : 5);
            continue;
        }
        struct pollfd reader = {.fd = channel[0], .events = POLLIN};
        int ready = poll(&reader, 1, (int)left);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) break;
        ssize_t count = read(channel[0], output + used, RULESET_LIMIT - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) break;
        if (!count) complete = 1;
        else used += (size_t)count;
    }
    close(channel[0]);
    if (child > 0 && reaped != child) {
        /* An unreaped direct child cannot have had its PID recycled. */
        if (reaped >= 0 || errno != ECHILD) kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
    }
    if (child <= 0 || reaped != child || !complete || !WIFEXITED(status) || WEXITSTATUS(status) ||
        !used || memchr(output, '\0', used)) return 0;
    output[used] = '\0';
    return 1;
}

static const char *legacy_attachment(char *output)
{
    int prerouting = 0, output_jump = 0, out_rule = 0, pre_rule = 0, pre_extra = 0;
    int bypass = 0, redirect = 0, entry = 0, other_entry = 0;
    int in_nat = 0, nat_complete = 0;
    char *state;
    for (char *line = strtok_r(output, "\n", &state); line; line = strtok_r(NULL, "\n", &state)) {
        if (*line == '*') {
            in_nat = !strcmp(line, "*nat");
            if (in_nat && nat_complete) return NULL;
            continue;
        }
        if (!in_nat) continue;
        if (!strcmp(line, "COMMIT")) {
            nat_complete = 1;
            in_nat = 0;
        } else if (!strncmp(line, ":PREROUTING ", sizeof(":PREROUTING ") - 1)) prerouting = 1;
        else if (!strcmp(line, "-A OUTPUT -p tcp -j TP_OUT")) output_jump++;
        else if (!strcmp(line, "-A TP_OUT -j TP_RULE")) out_rule++;
        else if (!strcmp(line, "-A TP_PRE -j TP_RULE")) pre_rule++;
        else if (!strncmp(line, "-A TP_PRE ", sizeof("-A TP_PRE ") - 1)) pre_extra++;
        else if (!strcmp(line, "-A TP_RULE -m mark --mark 0x80/0x80 -j RETURN")) bypass++;
        else if (!strcmp(line, "-A TP_RULE -p tcp -j REDIRECT --to-ports 52345")) redirect++;
        else if (!strcmp(line, "-A PREROUTING -p tcp -j TP_PRE")) entry++;
        else if (!strncmp(line, "-A PREROUTING ", sizeof("-A PREROUTING ") - 1) &&
                 strstr(line, " TP_PRE")) other_entry++;
    }
    if (!nat_complete || !prerouting || output_jump != 1 || out_rule != 1 ||
        bypass != 1 || redirect != 1) return NULL;
    if (entry > 1 || other_entry || pre_rule > 1 || pre_extra) return "unknown";
    return entry && pre_rule ? "attached" : "missing";
}

static int connmark_rule(const char *line, const char *rule)
{
    size_t length = strlen(rule);
    return !strncmp(line, rule, length) &&
           (!line[length] || !strcmp(line + length, " --nfmask 0xffffffff --ctmask 0xffffffff"));
}

static int tproxy_bypass(const char *rule)
{
    if (!strncmp(rule, "-d ", 3)) {
        const char *end = strchr(rule + 3, ' ');
        return end && end > rule + 3 && !strcmp(end, " -j RETURN");
    }
    return !strcmp(rule, "-i docker+ -j RETURN") || !strcmp(rule, "-i br+ -j RETURN") ||
           !strcmp(rule, "-i veth+ -j RETURN") || !strcmp(rule, "-i ppp+ -j RETURN") ||
           !strcmp(rule, "-p tcp -m tcp --dport 53 -j TP_MARK") ||
           !strcmp(rule, "-p udp -m udp --dport 53 -j TP_MARK") ||
           !strcmp(rule, "-m mark --mark 0x40/0xc0 -j RETURN");
}

static const char *legacy_tproxy_attachment(char *output, int ipv6)
{
    static const char *const out[] = {
        "-m mark --mark 0x80/0x80 -j RETURN",
        "-p tcp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j TP_RULE",
        "-p udp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j TP_RULE",
    };
    static const char *const pre[] = {
        "-i lo -m mark ! --mark 0x40/0xc0 -j RETURN",
        "-p tcp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j TP_RULE",
        "-p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j TP_RULE",
    };
    static const char *const mark[] = {
        "-p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j MARK --set-xmark 0x40/0x40",
        "-p udp -m conntrack --ctstate NEW -j MARK --set-xmark 0x40/0x40",
    };
    enum { OUT_COUNT = 3, PRE_COUNT = 5, MARK_COUNT = 3 };
    const char *listen = ipv6 ? "::1" : "127.0.0.1";
    int in_table = 0, complete = 0, prerouting = 0, out_jump = 0, pre_jump = 0;
    int out_count = 0, pre_count = 0, mark_count = 0, rule_count = 0, to_mark = 0;
    int invalid = 0;
    char *cursor;
    for (char *line = strtok_r(output, "\n", &cursor); line; line = strtok_r(NULL, "\n", &cursor)) {
        if (*line == '*') {
            in_table = !strcmp(line, "*mangle");
            if (in_table && complete) return NULL;
            continue;
        }
        if (!in_table) continue;
        if (!strcmp(line, "COMMIT")) { complete = 1; in_table = 0; }
        else if (!strncmp(line, ":PREROUTING ", sizeof(":PREROUTING ") - 1)) prerouting = 1;
        else if (!strcmp(line, "-A OUTPUT -j TP_OUT")) ++out_jump;
        else if (!strcmp(line, "-A PREROUTING -j TP_PRE")) ++pre_jump;
        else if (!strncmp(line, "-A TP_OUT ", sizeof("-A TP_OUT ") - 1)) {
            if (out_count >= OUT_COUNT || strcmp(line + 10, out[out_count])) invalid = 1;
            ++out_count;
        } else if (!strncmp(line, "-A TP_PRE ", sizeof("-A TP_PRE ") - 1)) {
            const char *rule = line + 10;
            if (pre_count < 3) invalid |= strcmp(rule, pre[pre_count]) != 0;
            else if (pre_count < PRE_COUNT) {
                char target[128];
                int length = snprintf(target, sizeof(target),
                    "-p %s -m mark --mark 0x40/0xc0 -j TPROXY --on-port 52345 --on-ip %s",
                    pre_count == 3 ? "tcp" : "udp", listen);
                if (length <= 0 || (size_t)length >= sizeof(target) || strncmp(rule, target, (size_t)length) ||
                    (rule[length] && strcmp(rule + length, " --tproxy-mark 0x0/0x0"))) invalid = 1;
            } else invalid = 1;
            ++pre_count;
        } else if (!strncmp(line, "-A TP_MARK ", sizeof("-A TP_MARK ") - 1)) {
            const char *rule = line + 11;
            if (mark_count < 2) invalid |= strcmp(rule, mark[mark_count]) != 0;
            else if (mark_count != 2 || !connmark_rule(rule, "-j CONNMARK --save-mark")) invalid = 1;
            ++mark_count;
        } else if (!strncmp(line, "-A TP_RULE ", sizeof("-A TP_RULE ") - 1)) {
            const char *rule = line + 11;
            if (to_mark) invalid = 1;
            else if (!rule_count) invalid |= !connmark_rule(rule, "-j CONNMARK --restore-mark");
            else if (rule_count == 1) invalid |= strcmp(rule, "-m mark --mark 0x40/0xc0 -j RETURN") != 0;
            else if (!strcmp(rule, "-j TP_MARK")) to_mark = 1;
            else invalid |= !tproxy_bypass(rule);
            ++rule_count;
        } else if (!strncmp(line, "-A ", 3) && (strstr(line, " -j TP_PRE") || strstr(line, " -g TP_PRE"))) {
            invalid = 1;
        }
    }
    if (!complete || !prerouting || !out_jump || (!pre_count && !mark_count)) return NULL;
    if (invalid || out_jump != 1 || pre_jump > 1 || out_count != OUT_COUNT ||
        pre_count != PRE_COUNT || mark_count != MARK_COUNT || !to_mark) return "unknown";
    return pre_jump ? "attached" : "missing";
}

static const char *read_legacy(const char *path, const char *alternate, char *output, enum lan_mode mode, int ipv6,
                               const volatile sig_atomic_t *stopping)
{
    if (access(path, X_OK)) path = alternate;
    /* Listing all loaded tables avoids iptables trying to autoload a named table. */
    char *const args[] = {(char *)path, NULL};
    if (!read_rules(path, args, output, stopping)) return NULL;
    return mode == LAN_TPROXY ? legacy_tproxy_attachment(output, ipv6) : legacy_attachment(output);
}

static void tproxy_route_status(int family, const char **state, const char **reason)
{
    if (!strcmp(*state, "missing")) {
        *reason = "hook_missing";
        return;
    }
    if (strcmp(*state, "attached")) return;
    const char *issue = lan_tproxy_route_issue(family);
    if (issue && !strcmp(issue, "unknown")) *state = "unknown";
    else if (issue) {
        *state = "missing";
        *reason = issue;
    }
}

static int persist_witness(struct lan_redirect_repair *repair)
{
    if (repair->checkpoint_error) return 0;
    if (redirect_checkpoint_save(repair->checkpoint, repair->witness, repair->retry_at)) return 1;
    repair->checkpoint_error = 1;
    json_object_put(repair->witness);
    repair->witness = NULL;
    fputs("v2raya-helper: LAN REDIRECT restoration disabled because its state could not be saved\n", stderr);
    return 0;
}

void lan_ingress_init(struct lan_redirect_repair *repair, const char *path, const char *api, const char *config)
{
    if (!path) return;
    repair->checkpoint = redirect_checkpoint_open(path, api, config, &repair->witness, &repair->retry_at);
    if (repair->checkpoint) return;
    repair->checkpoint_error = 1;
    fputs("v2raya-helper: LAN REDIRECT restoration disabled because its state file is unavailable\n", stderr);
}

void lan_ingress_disarm(struct lan_redirect_repair *repair)
{
    if (!repair) return;
    repair->missing_since = 0;
    if (!repair->witness) return;
    json_object_put(repair->witness);
    repair->witness = NULL;
    persist_witness(repair);
}

void lan_ingress_close(struct lan_redirect_repair *repair)
{
    if (!repair) return;
    json_object_put(repair->witness);
    redirect_checkpoint_close(repair->checkpoint);
}

static int append_identity(json_object *witness, json_object *part)
{
    if (part && !json_object_array_add(witness, part)) return 1;
    json_object_put(part);
    return 0;
}

static json_object *current_witness(const struct core_watch_sample *core, const struct stat *file,
                                    unsigned long long listener, int families, json_object *config, json_object *rules)
{
    /* Bind to the generated file without recording any of its contents or credentials. */
    const char *serialized = json_object_to_json_string_ext(config, JSON_C_TO_STRING_PLAIN);
    if (!serialized) return NULL;
    char fingerprint[33];
    text_fingerprint(fingerprint, serialized);
    const uint64_t values[] = {core->owner, core->owner_started, core->core, core->core_started, core->port,
        listener, families, file->st_dev, file->st_ino, file->st_size,
        file->st_mtim.tv_sec, file->st_mtim.tv_nsec, file->st_ctim.tv_sec, file->st_ctim.tv_nsec};
    json_object *witness = json_object_new_array();
    if (!witness) return NULL;
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        if (!append_identity(witness, json_object_new_uint64(values[i]))) {
            json_object_put(witness);
            return NULL;
        }
    }
    if (append_identity(witness, json_object_new_string(fingerprint)) &&
        append_identity(witness, json_object_get(rules))) return witness;
    json_object_put(witness);
    return NULL;
}

static int same_file(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static int same_core(const struct core_watch_sample *a, const struct core_watch_sample *b)
{
    return a->owner == b->owner && a->owner_started == b->owner_started && a->core == b->core &&
           a->core_started == b->core_started && a->port == b->port;
}

static struct lan_ingress observe_native_table(struct lan_ingress_watch *watch, struct lan_ingress result,
                                              const char *api, const char *path, json_object *config,
                                              const struct core_watch_sample *core, const struct stat *netns,
                                              int nft_loaded, char *output, const volatile sig_atomic_t *stopping)
{
    struct stat file;
    if (stat(path, &file) || !S_ISREG(file.st_mode)) {
        *watch = (struct lan_ingress_watch){0};
        return result;
    }
    if (result.backend) {
        if (!strcmp(result.backend, "nftables") && strcmp(result.ipv4, "unknown")) {
            *watch = (struct lan_ingress_watch){.core = *core, .config = file,
                                                .families = strcmp(result.ipv6, "unknown") ? 2 : 1};
        } else {
            *watch = (struct lan_ingress_watch){0};
        }
        return result;
    }
    if (!watch->families || !same_core(&watch->core, core) || !same_file(&watch->config, &file)) {
        *watch = (struct lan_ingress_watch){0};
        return result;
    }

    /* A failed single-table lookup could mean missing permissions or an unreadable tool. */
    char *const args[] = {"nft", "-j", "list", "tables", "inet", NULL};
    if (!nft_loaded || !read_rules("/usr/sbin/nft", args, output, stopping) ||
        lan_ingress_nft_tables(output) != LAN_NFT_ABSENT) {
        watch->missing_since = 0;
        return result;
    }
    struct core_watch_sample fresh = {0};
    if (*stopping || core_watch_sample(api, path, config, &fresh) != CORE_WATCH_HEALTHY ||
        !same_core(core, &fresh) || !same_network(fresh.owner, netns) || !same_network(fresh.core, netns) ||
        stat(path, &file) || !same_file(&watch->config, &file)) {
        *watch = (struct lan_ingress_watch){0};
        return result;
    }
    int64_t now = probe_clock_ms();
    if (!watch->missing_since || now < watch->missing_since) watch->missing_since = now;
    if (now - watch->missing_since < 1000) return result;
    return (struct lan_ingress){.mode = "redirect", .backend = "nftables", .ipv4 = "missing",
        .ipv6 = watch->families == 2 ? "missing" : "unknown", .reason = "table_missing"};
}

static int allows_redirect_restore(const struct v2raya_api *api)
{
    char error[128];
    json_object *doc = v2raya_api_version_data(api, error, sizeof(error));
    json_object *lite = json_object_object_get(doc, "lite");
    int supported = doc && capability_decide(doc, FEATURE_REDIRECT_RESTORE, error, sizeof(error)) &&
                    json_object_is_type(lite, json_type_int) && json_object_get_int(lite) == 0;
    json_object_put(doc);
    if (!supported) return 0;

    doc = v2raya_api_setting_data(api, error, sizeof(error));
    json_object *setting = json_object_object_get(doc, "setting");
    json_object *mode = json_object_object_get(setting, "transparent");
    int enabled = is_string(json_object_object_get(setting, "transparentType"), "redirect") &&
                  (is_string(mode, "proxy") || is_string(mode, "whitelist") ||
                   is_string(mode, "gfwlist") || is_string(mode, "pac"));
    json_object_put(doc);
    if (!enabled) return 0;

    /* This read rejects requests while stock v2rayA is carrying out a Stop or a change. */
    doc = v2raya_api_touch_data(api, error, sizeof(error));
    json_object *running = json_object_object_get(doc, "running"), *paused = NULL;
    int allowed = json_object_is_type(running, json_type_boolean) && json_object_get_boolean(running) &&
                  (!json_object_object_get_ex(doc, "networkPaused", &paused) ||
                   (json_object_is_type(paused, json_type_boolean) && !json_object_get_boolean(paused)));
    json_object_put(doc);
    return allowed;
}

static void consider_restore(struct lan_redirect_repair *repair, const struct v2raya_api *api,
                             const char *config_path, json_object *config, json_object *rules,
                             struct lan_ingress observed, uint32_t generation,
                             const struct core_watch_sample *core, const struct stat *netns,
                             const volatile sig_atomic_t *stopping)
{
    if (*stopping || repair->checkpoint_error) return;
    uint32_t after = 0;
    struct stat file;
    unsigned long long listener = rules ? core_watch_redirect_listener(core) : 0;
    if (!listener || stat(config_path, &file) || !S_ISREG(file.st_mode)) {
        if (!*stopping) lan_ingress_disarm(repair);
        return;
    }
    if (!generation || !lan_ingress_generation(&after) || after != generation) {
        repair->missing_since = 0;
        return;
    }

    int families = strcmp(observed.ipv6, "unknown") ? 2 : 1;
    json_object *witness = current_witness(core, &file, listener, families, config, rules);
    if (!witness) {
        lan_ingress_disarm(repair);
        return;
    }
    int same = repair->witness && json_object_equal(repair->witness, witness);
    if (!strcmp(observed.ipv4, "attached")) {
        if (!same) {
            json_object_put(repair->witness);
            repair->witness = witness;
            persist_witness(repair);
        } else json_object_put(witness);
        repair->missing_since = 0;
        return;
    }
    json_object_put(witness);
    if (!same || strcmp(observed.ipv4, "missing")) {
        lan_ingress_disarm(repair);
        return;
    }

    int64_t now = probe_clock_ms();
    if (!repair->missing_since || now < repair->missing_since) repair->missing_since = now;
    if (now - repair->missing_since < 1000 || now < repair->retry_at || *stopping) return;

    struct core_watch_peer peer = {.api = api->base, .stopping = stopping, .expected = core};
    struct v2raya_api verified = *api;
    verified.connected_peer = core_watch_verify_peer;
    verified.peer_context = &peer;
    if (!allows_redirect_restore(&verified)) {
        if (!*stopping) lan_ingress_disarm(repair);
        return;
    }

    json_object *fresh = node_config_read(config_path);
    struct core_watch_sample current = {0};
    struct stat verified_file;
    int unchanged = fresh && json_object_equal(config, fresh) &&
        core_watch_sample(api->base, config_path, fresh, &current) == CORE_WATCH_HEALTHY &&
        same_core(core, &current) && same_network(current.owner, netns) && same_network(current.core, netns) &&
        core_watch_redirect_listener(&current) == listener && !stat(config_path, &verified_file) &&
        same_file(&file, &verified_file);
    json_object_put(fresh);
    if (!unchanged) {
        if (!*stopping) lan_ingress_disarm(repair);
        return;
    }
    if (*stopping) return;
    /* Kernel rejects this write if anything changed since the bracket around the rules snapshot. */
    repair->retry_at = probe_clock_ms() + 60000;
    if (!persist_witness(repair) || *stopping) return;
    if (lan_ingress_restore(generation, families)) {
        fputs("v2raya-helper: restored the stock LAN REDIRECT rule\n", stderr);
    } else {
        repair->retry_at = probe_clock_ms() + 5000;
        persist_witness(repair);
    }
    repair->missing_since = 0;
}

struct lan_ingress lan_ingress_observe(const struct v2raya_api *api, const char *config_path, json_object *config,
                                      struct lan_ingress_watch *watch, struct lan_redirect_repair *repair,
                                      const volatile sig_atomic_t *stopping)
{
    struct lan_ingress result = {0};
    struct core_watch_sample core = {0};
    struct stat netns;
    if (*stopping) return result;
    enum lan_mode mode = stock_lan_mode(config);
    if (!mode || stat("/proc/self/ns/net", &netns) ||
        core_watch_sample(api->base, config_path, config, &core) != CORE_WATCH_HEALTHY ||
        !same_network(core.owner, &netns) || !same_network(core.core, &netns)) {
        if (!*stopping) lan_ingress_disarm(repair);
        *watch = (struct lan_ingress_watch){0};
        return result;
    }
    if (mode == LAN_TPROXY) {
        lan_ingress_disarm(repair);
        *watch = (struct lan_ingress_watch){0};
    }

    char *output = malloc(RULESET_LIMIT);
    if (!output) {
        lan_ingress_disarm(repair);
        watch->missing_since = 0;
        return result;
    }
    int nft_loaded = nftables_loaded();
    uint32_t generation = 0;
    json_object *rules = NULL;
    if (mode == LAN_REDIRECT && nft_loaded && repair && !repair->checkpoint_error &&
        lan_ingress_generation(&generation)) {
        char *const nft_full[] = {"nft", "-j", "list", "table", "inet", "v2raya", NULL};
        if (read_rules("/usr/sbin/nft", nft_full, output, stopping))
            result = lan_ingress_parse_nft(output, &rules);
    }
    if (nft_loaded && !rules) {
        char *const nft_args[] = {"nft", "-j", "-t", "list", "table", "inet", "v2raya", NULL};
        if (read_rules("/usr/sbin/nft", nft_args, output, stopping)) {
            result = mode == LAN_TPROXY ? lan_tproxy_parse_nft(output) : lan_ingress_parse_nft(output, NULL);
        }
    }
    const char *v4 = NULL, *v6 = NULL;
    if (nft_loaded || !access("/sys/module/ip_tables", F_OK))
        v4 = read_legacy("/usr/sbin/iptables-save", "/usr/sbin/iptables-nft-save", output, mode, 0, stopping);
    if (nft_loaded || !access("/sys/module/ip6_tables", F_OK))
        v6 = read_legacy("/usr/sbin/ip6tables-save", "/usr/sbin/ip6tables-nft-save", output, mode, 1, stopping);
    if (*stopping) {
        result = (struct lan_ingress){0};
    } else if (!same_network(core.owner, &netns) || !same_network(core.core, &netns) ||
        (result.backend && (v4 || v6))) {
        lan_ingress_disarm(repair);
        *watch = (struct lan_ingress_watch){0};
        result = (struct lan_ingress){0};
    } else {
        if (v4 || v6) {
            lan_ingress_disarm(repair);
            result = (struct lan_ingress){.mode = mode == LAN_TPROXY ? "tproxy" : "redirect",
                .backend = "iptables", .ipv4 = v4 ? v4 : "unknown", .ipv6 = v6 ? v6 : "unknown"};
        } else if (mode == LAN_REDIRECT && repair) {
            consider_restore(repair, api, config_path, config, rules, result, generation, &core, &netns, stopping);
        }
        if (mode == LAN_REDIRECT) {
            result = observe_native_table(watch, result, api->base, config_path, config, &core,
                                          &netns, nft_loaded, output, stopping);
        } else if (result.backend) {
            tproxy_route_status(AF_INET, &result.ipv4, &result.ipv4_reason);
            tproxy_route_status(AF_INET6, &result.ipv6, &result.ipv6_reason);
        }
    }
    json_object_put(rules);
    free(output);
    return result;
}
