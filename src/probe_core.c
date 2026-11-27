#define _GNU_SOURCE
#include "probe_core.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int put(json_object *object, const char *key, json_object *value)
{
	if (!value) return 0;
	if (!(key ? json_object_object_add(object, key, value) : json_object_array_add(object, value))) return 1;
	json_object_put(value);
	return 0;
}

static json_object *child_object(json_object *parent, const char *key)
{
	json_object *child;
	if (json_object_object_get_ex(parent, key, &child))
		return json_object_is_type(child, json_type_object) ? child : NULL;
	child = json_object_new_object();
	return put(parent, key, child) ? child : NULL;
}

static json_object *socks_inbound(const char *tag, int port)
{
	json_object *inbound = json_object_new_object(), *settings = json_object_new_object();
	if (put(inbound, "tag", json_object_new_string(tag)) && put(inbound, "listen", json_object_new_string("127.0.0.1")) &&
	    put(inbound, "port", json_object_new_int(port)) && put(inbound, "protocol", json_object_new_string("socks")) &&
	    put(settings, "auth", json_object_new_string("noauth")) && put(settings, "udp", json_object_new_boolean(0)) &&
	    put(inbound, "settings", json_object_get(settings))) {
		json_object_put(settings);
		return inbound;
	}
	json_object_put(settings);
	json_object_put(inbound);
	return NULL;
}

/* Keep the server's own socket mark, which v2rayA sets to pass its
 * transparent proxy; otherwise use the helper's. */
static json_object *marked_copy(json_object *outbound, const char *tag, uint32_t mark)
{
	json_object *copy = NULL;
	if (json_object_deep_copy(outbound, &copy, NULL) || !put(copy, "tag", json_object_new_string(tag))) goto fail;
	if (mark) {
		json_object *stream = child_object(copy, "streamSettings");
		json_object *sockopt = stream ? child_object(stream, "sockopt") : NULL;
		if (!sockopt) goto fail;
		if (!json_object_object_get_ex(sockopt, "mark", NULL) && !put(sockopt, "mark", json_object_new_int64(mark)))
			goto fail;
	}
	return copy;
fail:
	json_object_put(copy);
	return NULL;
}

static json_object *route(const char *inbound, const char *outbound)
{
	json_object *rule = json_object_new_object(), *tags = json_object_new_array();
	if (put(tags, NULL, json_object_new_string(inbound)) && put(rule, "type", json_object_new_string("field")) &&
	    put(rule, "inboundTag", json_object_get(tags)) && put(rule, "outboundTag", json_object_new_string(outbound))) {
		json_object_put(tags);
		return rule;
	}
	json_object_put(tags);
	json_object_put(rule);
	return NULL;
}

json_object *probe_core_config(json_object *const *outbounds, const int *ports, size_t count, uint32_t mark)
{
	json_object *config = json_object_new_object(), *log = json_object_new_object();
	json_object *inbounds = json_object_new_array(), *copies = json_object_new_array();
	json_object *routing = json_object_new_object(), *rules = json_object_new_array();
	int ok = put(log, "loglevel", json_object_new_string("none")) && put(config, "log", json_object_get(log)) &&
	         put(config, "inbounds", json_object_get(inbounds)) && put(config, "outbounds", json_object_get(copies)) &&
	         put(routing, "rules", json_object_get(rules)) && put(config, "routing", json_object_get(routing));
	for (size_t i = 0; ok && i < count; i++) {
		char in[24], out[24];
		snprintf(in, sizeof(in), "in%zu", i);
		snprintf(out, sizeof(out), "out%zu", i);
		ok = put(inbounds, NULL, socks_inbound(in, ports[i])) && put(copies, NULL, marked_copy(outbounds[i], out, mark)) &&
		     put(rules, NULL, route(in, out));
	}
	json_object_put(log);
	json_object_put(inbounds);
	json_object_put(copies);
	json_object_put(routing);
	json_object_put(rules);
	if (ok) return config;
	json_object_put(config);
	return NULL;
}

int probe_core_ports(int *ports, size_t count)
{
	int sockets[16], result = 0;
	if (count > sizeof(sockets) / sizeof(sockets[0])) return -1;
	size_t opened = 0;
	/* Hold every socket until all are chosen, so the ports are distinct. */
	for (; opened < count; opened++) {
		struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
		socklen_t size = sizeof(address);
		sockets[opened] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (sockets[opened] < 0 || bind(sockets[opened], (struct sockaddr *)&address, size) ||
		    getsockname(sockets[opened], (struct sockaddr *)&address, &size)) {
			result = -1;
			if (sockets[opened] >= 0) opened++;
			break;
		}
		ports[opened] = ntohs(address.sin_port);
	}
	while (opened) close(sockets[--opened]);
	return result;
}

static int64_t monotonic_ms(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec * INT64_C(1000) + now.tv_nsec / 1000000;
}

static int accepts(int port)
{
	struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port),
	                              .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) return 0;
	int error = 0;
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		error = errno;
		if (error == EINPROGRESS) {
			struct pollfd event = {.fd = fd, .events = POLLOUT};
			socklen_t length = sizeof(error);
			if (poll(&event, 1, 50) != 1 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length)) error = EIO;
		}
	}
	close(fd);
	return !error;
}

static void run_child(pid_t parent, int input, const struct core_kind *kind, const char *binary)
{
	if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0 || getppid() != parent || dup2(input, STDIN_FILENO) < 0) _exit(126);
	int quiet = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (quiet < 0 || dup2(quiet, STDOUT_FILENO) < 0 || dup2(quiet, STDERR_FILENO) < 0) _exit(126);
	char *argv[8] = {(char *)binary};
	size_t count = 1;
	for (const char *const *arg = kind->run_args; *arg && count < 7; arg++) argv[count++] = (char *)*arg;
	argv[count] = NULL;
	/* No inherited settings such as XRAY_LOCATION_CONFDIR; the probe needs no geo files. */
	char *const envp[] = {NULL};
	execve(binary, argv, envp);
	_exit(126);
}

pid_t probe_core_start(const struct core_kind *kind, const char *binary, json_object *config,
                       const int *ports, size_t count, long startup_ms)
{
	if (!kind || !binary || *binary != '/' || !config || !count) return -1;
	const char *text = json_object_to_json_string_ext(config, JSON_C_TO_STRING_PLAIN);
	int input[2];
	if (!text || pipe2(input, O_CLOEXEC)) return -1;
	pid_t parent = getpid(), core = fork();
	if (core == 0) run_child(parent, input[0], kind, binary);
	close(input[0]);
	size_t length = strlen(text), written = 0;
	while (core > 0 && written < length) {
		ssize_t n = write(input[1], text + written, length - written);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) break;
		written += (size_t)n;
	}
	close(input[1]);
	if (core < 0) return -1;
	if (written < length) {
		probe_core_stop(core);
		return -1;
	}
	int64_t deadline = monotonic_ms() + startup_ms;
	for (;;) {
		if (waitpid(core, NULL, WNOHANG) == core) return -1;
		size_t ready = 0;
		while (ready < count && accepts(ports[ready])) ready++;
		if (ready == count) return core;
		if (monotonic_ms() >= deadline) break;
		struct timespec pause = {.tv_nsec = 20 * 1000000};
		nanosleep(&pause, NULL);
	}
	probe_core_stop(core);
	return -1;
}

void probe_core_stop(pid_t core)
{
	if (core <= 0) return;
	kill(core, SIGKILL);
	while (waitpid(core, NULL, 0) < 0 && errno == EINTR) {}
}
