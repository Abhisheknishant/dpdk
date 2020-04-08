/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <dlfcn.h>

/* we won't link against libbsd, so just always use DPDKs-specific strlcpy */
#undef RTE_USE_LIBBSD
#include <rte_string_fns.h>
#include <rte_common.h>
#include <rte_spinlock.h>
#include <rte_version.h>

#include "rte_telemetry.h"

#define MAX_CMD_LEN 56
#define MAX_OUTPUT_LEN (1024 * 16)

static int
list_commands(const char *cmd __rte_unused, const char *params __rte_unused,
		char *buffer, int buf_len);

static int
handle_info(const char *cmd __rte_unused, const char *params __rte_unused,
		char *buffer, int buf_len);

static void *
client_handler(void *socket);

struct cmd_callback {
	char cmd[MAX_CMD_LEN];
	telemetry_cb fn;
};

struct socket {
	int sock;
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	handler fn;
};
static struct socket v2_socket; /* socket for v2 telemetry */
static char telemetry_log_error[1024]; /* Will contain error on init failure */
/* list of command callbacks, with one command registered by default */
static struct cmd_callback callbacks[TELEMETRY_MAX_CALLBACKS];
static int num_callbacks; /* How many commands are registered */
/* Used when accessing or modifying list of command callbacks */
static rte_spinlock_t callback_sl = RTE_SPINLOCK_INITIALIZER;

int
rte_telemetry_register_cmd(const char *cmd, telemetry_cb fn)
{
	int i = 0;

	if (strlen(cmd) >= MAX_CMD_LEN || fn == NULL || cmd[0] != '/')
		return -EINVAL;
	if (num_callbacks >= TELEMETRY_MAX_CALLBACKS)
		return -ENOENT;

	rte_spinlock_lock(&callback_sl);
	while (i < num_callbacks && strcmp(cmd, callbacks[i].cmd) > 0)
		i++;
	if (i != num_callbacks)
		/* Move elements to keep the list alphabetical */
		memmove(callbacks + i + 1, callbacks + i,
			sizeof(struct cmd_callback) * (num_callbacks - i));

	strlcpy(callbacks[i].cmd, cmd, MAX_CMD_LEN);
	callbacks[i].fn = fn;
	num_callbacks++;
	rte_spinlock_unlock(&callback_sl);

	return 0;
}

static int
list_commands(const char *cmd __rte_unused, const char *params __rte_unused,
		char *buffer, int buf_len)
{
	int i, ret, used = 0;

	used += strlcpy(buffer, "[", buf_len);
	for (i = 0; i < num_callbacks; i++) {
		ret = snprintf(buffer + used, buf_len - used, "\"%s\",",
				callbacks[i].cmd);
		if (ret + used >= buf_len)
			break;
		used += ret;
	}
	buffer[used - 1] = ']';
	return used;
}

static int
handle_info(const char *cmd __rte_unused, const char *params __rte_unused,
		char *buffer, int buf_len)
{
	int ret = snprintf(buffer, buf_len,
			"{\"pid\":%d, \"version\":\"%s\", \"max_output_len\":%d}",
			getpid(), rte_version(), MAX_OUTPUT_LEN);
	return ret >= buf_len ? -1 : ret;
}

static void
perform_command(telemetry_cb fn, const char *cmd, const char *param, int s)
{
	char out_buf[MAX_OUTPUT_LEN];

	int used = snprintf(out_buf,
			sizeof(out_buf), "{\"%s\":", cmd);
	int ret = fn(cmd, param, out_buf + used, sizeof(out_buf) - used);
	if (ret < 0) {
		used += strlcpy(out_buf + used, "null}\n",
				sizeof(out_buf) - used);
		if (write(s, out_buf, used) < 0)
			perror("Error writing to socket");
		return;
	}
	used += ret;
	used += strlcpy(out_buf + used, "}\n", sizeof(out_buf) - used);
	if (write(s, out_buf, used) < 0)
		perror("Error writing to socket");
}

static int
unknown_command(const char *cmd __rte_unused, const char *params __rte_unused,
		char *buffer, int buf_len)
{
	return snprintf(buffer, buf_len, "null");
}

static void *
client_handler(void *sock_id)
{
	int s = (int)(uintptr_t)sock_id;
	char buffer[1024];

	/* receive data is not null terminated */
	int bytes = read(s, buffer, sizeof(buffer));
	buffer[bytes] = 0;
	while (bytes > 0) {
		const char *cmd = strtok(buffer, ",");
		const char *param = strtok(NULL, ",");
		telemetry_cb fn = unknown_command;
		int i;

		rte_spinlock_lock(&callback_sl);
		for (i = 0; i < num_callbacks; i++)
			if (strcmp(cmd, callbacks[i].cmd) == 0) {
				fn = callbacks[i].fn;
				break;
			}

		rte_spinlock_unlock(&callback_sl);
		perform_command(fn, cmd, param, s);

		bytes = read(s, buffer, sizeof(buffer));
		buffer[bytes] = 0;
	}
	close(s);
	return NULL;
}

static void *
socket_listener(void *socket)
{
	while (1) {
		pthread_t th;
		struct socket *s = (struct socket *)socket;
		int s_accepted = accept(s->sock, NULL, NULL);
		if (s_accepted < 0) {
			snprintf(telemetry_log_error,
					sizeof(telemetry_log_error),
					"Error with accept, telemetry thread quitting\n");
			return NULL;
		}
		char info_buf[1024];
		if (handle_info(NULL, NULL, info_buf, sizeof(info_buf)) < 0)
			strlcpy(info_buf, "{}", sizeof(info_buf));
		if (write(s_accepted, info_buf, strlen(info_buf)) < 0)
			perror("Error writing to socket");
		pthread_create(&th, NULL, s->fn, (void *)(uintptr_t)s_accepted);
		pthread_detach(th);
	}
	return NULL;
}

static inline char *
get_socket_path(const char *runtime_dir, const int version)
{
	static char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/dpdk_telemetry.v%d",
			strlen(runtime_dir) ? runtime_dir : "/tmp", version);
	return path;
}

static void
unlink_sockets(void)
{
	if (v2_socket.path[0])
		unlink(v2_socket.path);
}

static int
create_socket(char *path)
{
	int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock < 0) {
		snprintf(telemetry_log_error, sizeof(telemetry_log_error),
				"Error with socket creation, %s",
				strerror(errno));
		return -1;
	}

	struct sockaddr_un sun = {.sun_family = AF_UNIX};
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	unlink(sun.sun_path);
	if (bind(sock, (void *) &sun, sizeof(sun)) < 0) {
		snprintf(telemetry_log_error, sizeof(telemetry_log_error),
				"Error binding socket: %s",
				strerror(errno));
		sun.sun_path[0] = 0;
		goto error;
	}

	if (listen(sock, 1) < 0) {
		snprintf(telemetry_log_error, sizeof(telemetry_log_error),
				"Error calling listen for socket: %s",
				strerror(errno));
		goto error;
	}

	return sock;

error:
	close(sock);
	unlink_sockets();
	return -1;
}

static int
telemetry_v2_init(const char *runtime_dir, const char **err_str)
{
	pthread_t t_new;

	rte_telemetry_register_cmd("/", list_commands);
	rte_telemetry_register_cmd("/info", handle_info);
	v2_socket.fn = client_handler;
	if (strlcpy(v2_socket.path, get_socket_path(runtime_dir, 2),
			sizeof(v2_socket.path)) >= sizeof(v2_socket.path)) {
		snprintf(telemetry_log_error, sizeof(telemetry_log_error),
				"Error with socket binding, path too long");
		return -1;
	}

	v2_socket.sock = create_socket(v2_socket.path);
	if (v2_socket.sock < 0) {
		*err_str = telemetry_log_error;
		return -1;
	}
	pthread_create(&t_new, NULL, socket_listener, &v2_socket);
	atexit(unlink_sockets);

	return 0;
}

int32_t
rte_telemetry_new_init(void)
{
	const char *error_str;
	if (telemetry_v2_init(rte_eal_get_runtime_dir(), &error_str) != 0) {
		printf("Error initialising telemetry - %s", error_str);
		return -1;
	}
	return 0;
}
