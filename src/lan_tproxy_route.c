#include "lan_tproxy_route.h"
#include <errno.h>
#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum {
    STOCK_MARK = 0x40, STOCK_MASK = 0xc0, STOCK_TABLE = 100,
    MAIN_PRIORITY = 32766,
    DUMP_TIMEOUT_MS = 1000, PACKET_LIMIT = 32 * 1024, DUMP_LIMIT = 4 * 1024 * 1024,
};

struct attribute {
    const unsigned char *data;
    size_t size;
};

struct inspection {
    int family;
    unsigned int loopback;
    unsigned int stock_rules, stock_routes;
    uint32_t stock_priority, competing_priority;
    int competing_rule, conflicting_route;
};

static int attributes(const unsigned char *data, size_t size, struct attribute *fields,
                      size_t count, int *extra)
{
    while (size >= sizeof(struct nlattr)) {
        struct nlattr header;
        memcpy(&header, data, sizeof(header));
        unsigned int type = header.nla_type & NLA_TYPE_MASK;
        size_t aligned = NLA_ALIGN(header.nla_len);
        if (header.nla_len < NLA_HDRLEN || aligned > size) return 0;
        if (type >= count) {
            *extra = 1;
        } else {
            if (fields[type].data) return 0;
            fields[type] = (struct attribute){data + NLA_HDRLEN, header.nla_len - NLA_HDRLEN};
        }
        data += aligned;
        size -= aligned;
    }
    return !size;
}

static int number(const struct attribute *field, uint32_t *value)
{
    if (!field->data) return 1;
    if (field->size != sizeof(*value)) return 0;
    memcpy(value, field->data, sizeof(*value));
    return 1;
}

static int stock_rule_fields(const struct attribute *fields)
{
    for (unsigned int i = 0; i <= FRA_MAX; ++i) {
        if (!fields[i].data) continue;
        switch (i) {
        case FRA_PRIORITY:
        case FRA_FWMARK:
        case FRA_FWMASK:
        case FRA_TABLE:
        case FRA_SUPPRESS_PREFIXLEN:
        case FRA_SUPPRESS_IFGROUP:
        case FRA_PROTOCOL:
            break;
        default:
            return 0;
        }
    }
    return 1;
}

static int default_rule(uint32_t table, uint32_t priority)
{
    return (table == RT_TABLE_LOCAL && priority == 0) ||
           (table == RT_TABLE_MAIN && priority == MAIN_PRIORITY) ||
           (table == RT_TABLE_DEFAULT && priority == MAIN_PRIORITY + 1);
}

static int inspect_rule(const unsigned char *body, size_t size, struct inspection *result)
{
    struct fib_rule_hdr rule;
    if (size < sizeof(rule)) return 0;
    memcpy(&rule, body, sizeof(rule));
    if (rule.family != result->family) return 0;
    struct attribute fields[FRA_MAX + 1] = {0};
    uint32_t table = rule.table, priority = 0, mark = 0, mask = 0;
    uint32_t prefix = UINT32_MAX, ifgroup = UINT32_MAX;
    int extra = 0;
    if (!attributes(body + sizeof(rule), size - sizeof(rule), fields, FRA_MAX + 1, &extra) ||
        !number(&fields[FRA_TABLE], &table) || !number(&fields[FRA_PRIORITY], &priority) ||
        !number(&fields[FRA_FWMARK], &mark) || !number(&fields[FRA_FWMASK], &mask) ||
        !number(&fields[FRA_SUPPRESS_PREFIXLEN], &prefix) ||
        !number(&fields[FRA_SUPPRESS_IFGROUP], &ifgroup) ||
        (fields[FRA_PROTOCOL].data && fields[FRA_PROTOCOL].size != 1)) return 0;

    unsigned char protocol = fields[FRA_PROTOCOL].data ? *fields[FRA_PROTOCOL].data : RTPROT_UNSPEC;
    int ordinary = !extra && !rule.src_len && !rule.dst_len && !rule.tos && !rule.res1 && !rule.res2 &&
                   rule.action == FR_ACT_TO_TBL && prefix == UINT32_MAX && ifgroup == UINT32_MAX &&
                   stock_rule_fields(fields);
    if (ordinary && !rule.flags && priority && priority < MAIN_PRIORITY &&
        table == STOCK_TABLE && mark == STOCK_MARK && mask == STOCK_MASK &&
        (protocol == RTPROT_UNSPEC || protocol == RTPROT_BOOT)) {
        ++result->stock_rules;
        result->stock_priority = priority;
    } else if (ordinary && !mark && !mask && !(rule.flags & ~FIB_RULE_PERMANENT) &&
               (protocol == RTPROT_KERNEL || protocol == RTPROT_UNSPEC) && default_rule(table, priority)) {
        return 1;
    } else if (rule.action != FR_ACT_NOP &&
               ((rule.flags & FIB_RULE_INVERT) || !((mark ^ STOCK_MARK) & mask & STOCK_MASK))) {
        /* An earlier overlapping rule can act on some of the same packets. */
        if (!result->competing_rule || priority < result->competing_priority)
            result->competing_priority = priority;
        result->competing_rule = 1;
    }
    return 1;
}

static int stock_route_fields(const struct attribute *fields)
{
    for (unsigned int i = 0; i <= RTA_MAX; ++i) {
        if (!fields[i].data) continue;
        switch (i) {
        case RTA_TABLE:
        case RTA_OIF:
        case RTA_PRIORITY:
        case RTA_PREF:
        case RTA_CACHEINFO:
            break;
        default:
            return 0;
        }
    }
    return 1;
}

static int inspect_route(const unsigned char *body, size_t size, struct inspection *result)
{
    struct rtmsg route;
    if (size < sizeof(route)) return 0;
    memcpy(&route, body, sizeof(route));
    if (route.rtm_family != result->family) return 0;
    struct attribute fields[RTA_MAX + 1] = {0};
    uint32_t table = route.rtm_table, interface = 0;
    int extra = 0;
    if (!attributes(body + sizeof(route), size - sizeof(route), fields, RTA_MAX + 1, &extra) ||
        !number(&fields[RTA_TABLE], &table) || !number(&fields[RTA_OIF], &interface)) return 0;
    if (table != STOCK_TABLE) return 1;

    unsigned int scope = result->family == AF_INET ? RT_SCOPE_HOST : RT_SCOPE_UNIVERSE;
    if (!extra && !route.rtm_dst_len && !route.rtm_src_len && !route.rtm_tos && !route.rtm_flags &&
        route.rtm_type == RTN_LOCAL && route.rtm_scope == scope && interface == result->loopback &&
        stock_route_fields(fields)) {
        ++result->stock_routes;
    } else {
        result->conflicting_route = 1;
    }
    return 1;
}

static int64_t clock_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int receive_dump(int fd, uint32_t port, uint32_t sequence, int rules, int64_t deadline,
                        struct inspection *result)
{
    size_t total = 0;
    while (total < DUMP_LIMIT) {
        int64_t now = clock_ms();
        if (now < 0 || now >= deadline) return 0;
        struct pollfd listener = {.fd = fd, .events = POLLIN};
        int ready = poll(&listener, 1, (int)(deadline - now));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || !(listener.revents & POLLIN)) return 0;

        unsigned char bytes[PACKET_LIMIT];
        struct sockaddr_nl sender;
        struct iovec storage = {.iov_base = bytes, .iov_len = sizeof(bytes)};
        struct msghdr reply = {.msg_name = &sender, .msg_namelen = sizeof(sender),
                               .msg_iov = &storage, .msg_iovlen = 1};
        ssize_t count = recvmsg(fd, &reply, 0);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0 || (reply.msg_flags & MSG_TRUNC) || (size_t)count > DUMP_LIMIT - total ||
            reply.msg_namelen != sizeof(sender) || sender.nl_family != AF_NETLINK ||
            sender.nl_pid || sender.nl_groups) return 0;
        total += (size_t)count;

        size_t offset = 0;
        while ((size_t)count - offset >= NLMSG_HDRLEN) {
            struct nlmsghdr header;
            memcpy(&header, bytes + offset, sizeof(header));
            size_t left = (size_t)count - offset;
            if (header.nlmsg_len < NLMSG_HDRLEN || header.nlmsg_len > left ||
                NLMSG_ALIGN(header.nlmsg_len) > left || header.nlmsg_seq != sequence ||
                header.nlmsg_pid != port || !(header.nlmsg_flags & NLM_F_MULTI) ||
                (header.nlmsg_flags & NLM_F_DUMP_INTR)) return 0;
            const unsigned char *body = bytes + offset + NLMSG_HDRLEN;
            size_t length = header.nlmsg_len - NLMSG_HDRLEN;
            offset += NLMSG_ALIGN(header.nlmsg_len);
            if (header.nlmsg_type == NLMSG_DONE) {
                int status;
                if (length < sizeof(status) || offset != (size_t)count) return 0;
                memcpy(&status, body, sizeof(status));
                return status == 0;
            }
            if (header.nlmsg_type != (rules ? RTM_NEWRULE : RTM_NEWROUTE) ||
                !(rules ? inspect_rule(body, length, result) : inspect_route(body, length, result))) return 0;
        }
        if (offset != (size_t)count) return 0;
    }
    return 0;
}

static int dump(int fd, uint32_t port, int rules, int64_t deadline, struct inspection *result)
{
    struct {
        struct nlmsghdr header;
        union {
            struct fib_rule_hdr rule;
            struct rtmsg route;
        } body;
    } request = {0};
    request.header.nlmsg_type = rules ? RTM_GETRULE : RTM_GETROUTE;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = rules ? 1 : 2;
    if (rules) {
        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.body.rule));
        request.body.rule.family = result->family;
    } else {
        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.body.route));
        request.body.route.rtm_family = result->family;
    }
    const struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    return sendto(fd, &request, request.header.nlmsg_len, 0,
                  (const struct sockaddr *)&kernel, sizeof(kernel)) == (ssize_t)request.header.nlmsg_len &&
           receive_dump(fd, port, request.header.nlmsg_seq, rules, deadline, result);
}

const char *lan_tproxy_route_issue(int family)
{
    if (family != AF_INET && family != AF_INET6) return "unknown";
    struct inspection result = {.family = family, .loopback = if_nametoindex("lo")};
    int64_t now = clock_ms();
    if (!result.loopback || now < 0) return "unknown";
    int64_t deadline = now + DUMP_TIMEOUT_MS;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0) return "unknown";
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    socklen_t size = sizeof(local);
    const char *issue = "unknown";
    if (!bind(fd, (const struct sockaddr *)&local, sizeof(local)) &&
        !getsockname(fd, (struct sockaddr *)&local, &size) && size == sizeof(local) &&
        local.nl_family == AF_NETLINK && local.nl_pid && dump(fd, local.nl_pid, 1, deadline, &result)) {
        if (!result.stock_rules && !result.competing_rule) {
            issue = "policy_missing";
        } else if (result.stock_rules == 1 &&
                   (!result.competing_rule || result.competing_priority > result.stock_priority) &&
                   dump(fd, local.nl_pid, 0, deadline, &result) &&
                   !result.conflicting_route && result.stock_routes <= 1) {
            issue = result.stock_routes ? NULL : "local_route_missing";
        }
    }
    close(fd);
    return issue;
}
