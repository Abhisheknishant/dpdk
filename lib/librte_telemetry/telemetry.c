/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
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

#include "rte_telemetry.h"
#include "rte_telemetry_legacy.h"

#define MAX_CMD_LEN 56

static int
list_commands(const char *cmd __rte_unused, const char *params __rte_unused,
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
static struct socket v1_socket; /* socket for v1 telemetry */
static char telemetry_log_error[1024]; /* Will contain error on init failure */
/* list of command callbacks, with one command registered by default */
static struct cmd_callback callbacks[TELEMETRY_MAX_CALLBACKS] = {
		{ .cmd = "/", .fn = list_commands },
};
static int num_callbacks = 1; /* How many commands are registered */
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

static void
perform_command(telemetry_cb fn, const char *cmd, const char *param, int s)
{
	char out_buf[1024 * 12];

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
		pthread_create(&th, NULL, s->fn, (void *)(uintptr_t)s_accepted);
		pthread_detach(th);
	}
	return NULL;
}

static inline char *
get_socket_path(const char *runtime_dir)
{
	static char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/dpdk_telemetry.%d",
			strlen(runtime_dir) ? runtime_dir : "/tmp", getpid());
	return path;
}

static void
unlink_sockets(void)
{
	if (v2_socket.path[0])
		unlink(v2_socket.path);
	if (v1_socket.path[0])
		unlink(v1_socket.path);
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
telemetry_legacy_init(const char *runtime_dir, const char **err_str)
{
	pthread_t t_old;

	if (num_legacy_callbacks == 1) {
		*err_str = "No legacy callbacks - error creating legacy socket";
		return -1;
	}

	v1_socket.fn = legacy_client_handler;
	if ((size_t) snprintf(v1_socket.path, sizeof(v1_socket.path),
			"%s/telemetry", runtime_dir)
			>= sizeof(v1_socket.path)) {
		snprintf(telemetry_log_error, sizeof(telemetry_log_error),
				"Error with socket binding, path too long");
		return -1;
	}
	v1_socket.sock = create_socket(v1_socket.path);
	if (v1_socket.sock < 0) {
		*err_str = telemetry_log_error;
		return -1;
	}
	pthread_create(&t_old, NULL, socket_listener, &v1_socket);

	return 0;
}

static int
telemetry_v2_init(const char *runtime_dir, const char **err_str)
{
	pthread_t t_new;

	v2_socket.fn = client_handler;
	if (strlcpy(v2_socket.path, get_socket_path(runtime_dir),
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
rte_telemetry_init(const char *runtime_dir, const char **err_str)
{
	if (telemetry_v2_init(runtime_dir, err_str) != 0) {
		printf("Error initialising telemetry - %s", *err_str);
		return -1;
	}
	if (telemetry_legacy_init(runtime_dir, err_str) != 0)
		printf("No telemetry legacy support- %s", *err_str);
	return 0;
}
