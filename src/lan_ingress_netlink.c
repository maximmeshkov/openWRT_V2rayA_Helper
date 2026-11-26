#include "lan_ingress_netlink.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum {
    RECEIVE_TIMEOUT_MS = 1000,
    SEQ_GET_GENERATION = 1, SEQ_BATCH_BEGIN, SEQ_FAMILY_SET, SEQ_FAMILY_ELEMENTS,
    SEQ_PREROUTING_RULE, SEQ_BATCH_END,
    FAMILY_SET_ID = 1,
    /* nft userspace datatype for NFPROTO, as written by stock nftables. */
    NFT_TYPE_NFPROTO = 2,
};

static const char table_name[] = "v2raya";
static const char anonymous_set_name[] = "__set%d";
static const struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};

struct request {
    unsigned char bytes[768];
    size_t length;
    int overflow;
};

static void append(struct request *request, const void *value, size_t size)
{
    if (size > sizeof(request->bytes) - request->length) {
        request->overflow = 1;
        return;
    }
    memcpy(request->bytes + request->length, value, size);
    request->length += size;
}

static void attribute(struct request *request, uint16_t type, const void *value, size_t size)
{
    const struct nlattr header = {.nla_len = NLA_HDRLEN + size, .nla_type = type};
    const unsigned char padding[NLA_ALIGNTO] = {0};
    append(request, &header, sizeof(header));
    if (size) append(request, value, size);
    append(request, padding, NLA_ALIGN(header.nla_len) - header.nla_len);
}

static void number(struct request *request, uint16_t type, uint32_t value)
{
    value = htonl(value);
    attribute(request, type, &value, sizeof(value));
}

static void name(struct request *request, uint16_t type, const char *value)
{
    attribute(request, type, value, strlen(value) + 1);
}

static size_t start_nested(struct request *request, uint16_t type)
{
    size_t start = request->length;
    attribute(request, type | NLA_F_NESTED, NULL, 0);
    return start;
}

static void end_nested(struct request *request, size_t start)
{
    uint16_t size = request->length - start;
    if (!request->overflow)
        memcpy(request->bytes + start + offsetof(struct nlattr, nla_len), &size, sizeof(size));
}

static uint16_t nft_message(uint16_t type)
{
    return (NFNL_SUBSYS_NFTABLES << 8) | type;
}

static size_t start_message(struct request *request, uint16_t type, uint16_t flags,
                            uint32_t sequence, uint8_t family)
{
    const struct nlmsghdr header = {.nlmsg_type = type, .nlmsg_flags = NLM_F_REQUEST | flags,
                                   .nlmsg_seq = sequence};
    const struct nfgenmsg body = {
        .nfgen_family = family, .version = NFNETLINK_V0,
        .res_id = htons(type == NFNL_MSG_BATCH_BEGIN || type == NFNL_MSG_BATCH_END ?
                        NFNL_SUBSYS_NFTABLES : 0),
    };
    size_t start = request->length;
    append(request, &header, sizeof(header));
    append(request, &body, sizeof(body));
    return start;
}

static void end_message(struct request *request, size_t start)
{
    uint32_t size = request->length - start;
    if (!request->overflow) memcpy(request->bytes + start, &size, sizeof(size));
}

static void add_family_element(struct request *request, uint16_t index, uint8_t family)
{
    size_t element = start_nested(request, index);
    size_t key = start_nested(request, NFTA_SET_ELEM_KEY);
    attribute(request, NFTA_DATA_VALUE, &family, sizeof(family));
    end_nested(request, key);
    end_nested(request, element);
}

static void add_family_set(struct request *request)
{
    size_t message = start_message(request, nft_message(NFT_MSG_NEWSET), NLM_F_CREATE | NLM_F_ACK,
                                   SEQ_FAMILY_SET, NFPROTO_INET);
    name(request, NFTA_SET_TABLE, table_name);
    name(request, NFTA_SET_NAME, anonymous_set_name);
    number(request, NFTA_SET_FLAGS, NFT_SET_ANONYMOUS | NFT_SET_CONSTANT);
    number(request, NFTA_SET_KEY_TYPE, NFT_TYPE_NFPROTO);
    number(request, NFTA_SET_KEY_LEN, 1);
    number(request, NFTA_SET_ID, FAMILY_SET_ID);
    end_message(request, message);

    message = start_message(request, nft_message(NFT_MSG_NEWSETELEM), NLM_F_CREATE | NLM_F_ACK,
                            SEQ_FAMILY_ELEMENTS, NFPROTO_INET);
    name(request, NFTA_SET_ELEM_LIST_TABLE, table_name);
    name(request, NFTA_SET_ELEM_LIST_SET, anonymous_set_name);
    number(request, NFTA_SET_ELEM_LIST_SET_ID, FAMILY_SET_ID);
    size_t elements = start_nested(request, NFTA_SET_ELEM_LIST_ELEMENTS);
    add_family_element(request, 1, NFPROTO_IPV4);
    add_family_element(request, 2, NFPROTO_IPV6);
    end_nested(request, elements);
    end_message(request, message);
}

struct expression {
    size_t element;
    size_t data;
};

static struct expression start_expression(struct request *request, const char *type)
{
    struct expression expr;
    expr.element = start_nested(request, NFTA_LIST_ELEM);
    name(request, NFTA_EXPR_NAME, type);
    expr.data = start_nested(request, NFTA_EXPR_DATA);
    return expr;
}

static void end_expression(struct request *request, struct expression expr)
{
    end_nested(request, expr.data);
    end_nested(request, expr.element);
}

static void load_metadata(struct request *request, uint32_t key)
{
    struct expression expr = start_expression(request, "meta");
    number(request, NFTA_META_KEY, key);
    number(request, NFTA_META_DREG, NFT_REG_1);
    end_expression(request, expr);
}

static void compare_byte(struct request *request, uint8_t expected)
{
    struct expression expr = start_expression(request, "cmp");
    number(request, NFTA_CMP_SREG, NFT_REG_1);
    number(request, NFTA_CMP_OP, NFT_CMP_EQ);
    size_t data = start_nested(request, NFTA_CMP_DATA);
    attribute(request, NFTA_DATA_VALUE, &expected, sizeof(expected));
    end_nested(request, data);
    end_expression(request, expr);
}

static void add_prerouting_rule(struct request *request, int dual)
{
    size_t message = start_message(request, nft_message(NFT_MSG_NEWRULE),
                                   NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK,
                                   SEQ_PREROUTING_RULE, NFPROTO_INET);
    name(request, NFTA_RULE_TABLE, table_name);
    name(request, NFTA_RULE_CHAIN, "tp_pre");
    size_t expressions = start_nested(request, NFTA_RULE_EXPRESSIONS);
    load_metadata(request, NFT_META_NFPROTO);
    if (dual) {
        struct expression expr = start_expression(request, "lookup");
        number(request, NFTA_LOOKUP_SREG, NFT_REG_1);
        name(request, NFTA_LOOKUP_SET, anonymous_set_name);
        number(request, NFTA_LOOKUP_SET_ID, FAMILY_SET_ID);
        end_expression(request, expr);
    } else {
        compare_byte(request, NFPROTO_IPV4);
    }
    load_metadata(request, NFT_META_L4PROTO);
    compare_byte(request, IPPROTO_TCP);
    struct expression expr = start_expression(request, "immediate");
    number(request, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
    size_t data = start_nested(request, NFTA_IMMEDIATE_DATA);
    size_t verdict = start_nested(request, NFTA_DATA_VERDICT);
    number(request, NFTA_VERDICT_CODE, (uint32_t)NFT_JUMP);
    name(request, NFTA_VERDICT_CHAIN, "tp_rule");
    end_nested(request, verdict);
    end_nested(request, data);
    end_expression(request, expr);
    end_nested(request, expressions);
    end_message(request, message);
}

static int64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static uint32_t read_generation(const unsigned char *payload, size_t length)
{
    struct nfgenmsg family;
    if (length < sizeof(family)) return 0;
    memcpy(&family, payload, sizeof(family));
    if (family.nfgen_family != AF_UNSPEC || family.version != NFNETLINK_V0) return 0;
    payload += sizeof(family);
    length -= sizeof(family);
    uint32_t generation = 0;
    while (length >= sizeof(struct nlattr)) {
        struct nlattr attribute;
        memcpy(&attribute, payload, sizeof(attribute));
        size_t aligned = NLA_ALIGN(attribute.nla_len);
        if (attribute.nla_len < NLA_HDRLEN || aligned > length) return 0;
        if ((attribute.nla_type & NLA_TYPE_MASK) == NFTA_GEN_ID) {
            if (generation || attribute.nla_len != NLA_HDRLEN + sizeof(generation)) return 0;
            memcpy(&generation, payload + NLA_HDRLEN, sizeof(generation));
            if (!generation) return 0;
        }
        payload += aligned;
        length -= aligned;
    }
    return length ? 0 : ntohl(generation);
}

static uint16_t acknowledged_type(uint32_t sequence)
{
    switch (sequence) {
    case SEQ_BATCH_BEGIN: return NFNL_MSG_BATCH_BEGIN;
    case SEQ_FAMILY_SET: return nft_message(NFT_MSG_NEWSET);
    case SEQ_FAMILY_ELEMENTS: return nft_message(NFT_MSG_NEWSETELEM);
    case SEQ_PREROUTING_RULE: return nft_message(NFT_MSG_NEWRULE);
    default: return 0;
    }
}

static int receive_reply(int fd, uint32_t port, uint32_t *generation, unsigned int pending)
{
    int64_t start = monotonic_ms();
    if (start < 0) return 0;
    for (;;) {
        int64_t now = monotonic_ms();
        int64_t left = start + RECEIVE_TIMEOUT_MS - now;
        if (now < 0 || left <= 0) return 0;
        struct pollfd reader = {.fd = fd, .events = POLLIN};
        int ready = poll(&reader, 1, (int)left);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || !(reader.revents & POLLIN)) return 0;

        unsigned char bytes[2048];
        struct sockaddr_nl address;
        struct iovec storage = {.iov_base = bytes, .iov_len = sizeof(bytes)};
        struct msghdr reply = {.msg_name = &address, .msg_namelen = sizeof(address),
                               .msg_iov = &storage, .msg_iovlen = 1};
        ssize_t received = recvmsg(fd, &reply, 0);
        if (received < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (received <= 0 || reply.msg_flags & MSG_TRUNC) return 0;
        if (reply.msg_namelen != sizeof(address) || address.nl_family != AF_NETLINK ||
            address.nl_pid || address.nl_groups) continue;

        size_t offset = 0;
        while ((size_t)received - offset >= NLMSG_HDRLEN) {
            struct nlmsghdr header;
            memcpy(&header, bytes + offset, sizeof(header));
            if (header.nlmsg_len < NLMSG_HDRLEN ||
                header.nlmsg_len > (size_t)received - offset) return 0;
            size_t aligned = NLMSG_ALIGN(header.nlmsg_len);
            if (aligned > (size_t)received - offset) return 0;
            const unsigned char *payload = bytes + offset + NLMSG_HDRLEN;
            size_t length = header.nlmsg_len - NLMSG_HDRLEN;
            offset += aligned;
            if (header.nlmsg_pid != port) continue;
            if (generation) {
                if (header.nlmsg_seq != SEQ_GET_GENERATION) continue;
                if (header.nlmsg_type != nft_message(NFT_MSG_NEWGEN)) return 0;
                *generation = read_generation(payload, length);
                return *generation != 0;
            }
            uint16_t type = acknowledged_type(header.nlmsg_seq);
            if (header.nlmsg_type != NLMSG_ERROR || !type) continue;
            struct nlmsgerr ack;
            if (length < sizeof(ack)) return 0;
            memcpy(&ack, payload, sizeof(ack));
            if (ack.msg.nlmsg_seq != header.nlmsg_seq || ack.msg.nlmsg_type != type || ack.error)
                return 0;
            pending &= ~(1U << header.nlmsg_seq);
        }
        if (offset != (size_t)received) return 0;
        if (!generation && !pending) return 1;
    }
}

static int exchange(const struct request *request, uint32_t *generation, unsigned int pending)
{
    if (request->overflow) return 0;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_NETFILTER);
    if (fd < 0) return 0;
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    socklen_t size = sizeof(local);
    int ok = !bind(fd, (const struct sockaddr *)&local, sizeof(local)) &&
             !getsockname(fd, (struct sockaddr *)&local, &size) && size == sizeof(local) &&
             local.nl_family == AF_NETLINK && local.nl_pid &&
             sendto(fd, request->bytes, request->length, 0,
                    (const struct sockaddr *)&kernel, sizeof(kernel)) == (ssize_t)request->length &&
             receive_reply(fd, local.nl_pid, generation, pending);
    close(fd);
    return ok;
}

int lan_ingress_generation(uint32_t *generation)
{
    if (!generation) return 0;
    *generation = 0;
    struct request request = {0};
    size_t message = start_message(&request, nft_message(NFT_MSG_GETGEN), 0,
                                   SEQ_GET_GENERATION, AF_UNSPEC);
    end_message(&request, message);
    return exchange(&request, generation, 0);
}

int lan_ingress_restore(uint32_t generation, int families)
{
    if (!generation || (families != 1 && families != 2)) return 0;
    struct request request = {0};
    /* nfnetlink reports operation acknowledgements after processing the full batch. */
    unsigned int acks = 1U << SEQ_PREROUTING_RULE;
    size_t message = start_message(&request, NFNL_MSG_BATCH_BEGIN, 0, SEQ_BATCH_BEGIN, AF_UNSPEC);
    number(&request, NFNL_BATCH_GENID, generation);
    end_message(&request, message);
    if (families == 2) {
        add_family_set(&request);
        acks |= (1U << SEQ_FAMILY_SET) | (1U << SEQ_FAMILY_ELEMENTS);
    }
    add_prerouting_rule(&request, families == 2);
    message = start_message(&request, NFNL_MSG_BATCH_END, 0, SEQ_BATCH_END, AF_UNSPEC);
    end_message(&request, message);
    return exchange(&request, NULL, acks);
}
