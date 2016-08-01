/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file radmin.c
 * @brief Control a running radiusd process.
 *
 * @copyright 2012-2016 The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2012 Alan DeKok <aland@deployingradius.com>
 */
RCSID("$Id$")

#include <assert.h>

#include <pwd.h>
#include <grp.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#ifdef HAVE_LIBREADLINE

#if defined(HAVE_READLINE_READLINE_H)
#  include <readline/readline.h>
#elif defined(HAVE_READLINE_H)
#  include <readline.h>
#endif /* !defined(HAVE_READLINE_H) */

#ifdef HAVE_READLINE_HISTORY
#  if defined(HAVE_READLINE_HISTORY_H)
#    include <readline/history.h>
#    define USE_READLINE_HISTORY (1)
#  elif defined(HAVE_HISTORY_H)
#    include <history.h>
#    define USE_READLINE_HISTORY (1)
#endif /* defined(HAVE_READLINE_HISTORY_H) */
#endif /* HAVE_READLINE_HISTORY */
#endif /* HAVE_LIBREADLINE */

#define LOG_PREFIX "radmin - "

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/md5.h>
#include <freeradius-devel/channel.h>

#define MAX_COMMANDS (4)

#define RADMIN_EVENT_LOOP_EXIT_SUCCESS	INT32_MAX

/*
 *	For configuration file stuff.
 */
static char const *progname = "radmin";
static char const *radmin_version = "radmin version " RADIUSD_VERSION_STRING
#ifdef RADIUSD_VERSION_COMMIT
" (git #" STRINGIFY(RADIUSD_VERSION_COMMIT) ")"
#endif
", built on " __DATE__ " at " __TIME__;

typedef enum {
	RADMIN_CONN_NONE = 0,				//!< Don't know, never connected.
	RADMIN_CONN_UNIX,				//!< Connect via unix socket.
	RADMIN_CONN_TCP					//!< Connect via TCP.
} radmin_conn_type_t;

/** A connection to a server
 *
 */
typedef struct radmin_conn {
	fr_event_list_t		*event_list;		//!< Event list this fd is serviced by.
	int			fd;			//!< Control socket descriptor.

	char			*last_command;		//!< Last command we executed on this connection.
	char			*server;		//!< Path or FQDN of server we're connected to.
	char			*secret;		//!< We use to authenticate ourselves to the server.

	bool			nonblock;		//!< Whether this connection should operate in
							//!< non-blocking mode.
	bool			connected;		//!< Whether this connection is currently connected.

	fr_channel_buff_t	*buff;

	radmin_conn_type_t	type;			//!< Type of connection.
} radmin_conn_t;

/** Radmin state
 *
 * Many of the readline functions don't take callbacks, so we need
 * to use a global structure to communicate radmin state.
 */
typedef struct radmin_state {
	fr_event_list_t		*event_list;		//!< Our main event list.

	radmin_conn_t		*active_conn;		//!< Connection to remote entity.

	bool			batch;			//!< Whether we're in batch mode.
	bool			echo;			//!< Whether we should be echoing commands as they're issued.
	bool			unbuffered;		//!< Whether we're in unbuffered mode...
} radmin_state_t;

/** Main radmin state
 *
 */
static radmin_state_t state;

/*
 *	The rest of this is because the conffile.c, etc. assume
 *	they're running inside of the server.  And we don't (yet)
 *	have a "libfreeradius-server", or "libfreeradius-util".
 */
main_config_t main_config;

static int conn_reconnect(radmin_conn_t **conn, char const *command);

static void NEVER_RETURNS usage(int status)
{
	FILE *output = status ? stderr : stdout;
	fprintf(output, "Usage: %s [ args ]\n", progname);
	fprintf(output, "  -d raddb_dir    Configuration files are in \"raddbdir/*\".\n");
	fprintf(output, "  -D <dictdir>    Set main dictionary directory (defaults to " DICTDIR ").\n");
	fprintf(output, "  -e command      Execute 'command' and then exit.\n");
	fprintf(output, "  -E              Echo commands as they are being executed.\n");
	fprintf(output, "  -f socket_file  Open socket_file directly, without reading radius.conf\n");
	fprintf(output, "  -h              Print usage help information.\n");
	fprintf(output, "  -i input_file   Read commands from 'input_file'.\n");
	fprintf(output, "  -n name         Read raddb/name.conf instead of raddb/radiusd.conf\n");
	fprintf(output, "  -q              Reduce output verbosity\n");
	fprintf(output, "  -x              Increase output verbosity\n");
	exit(status);
}

static void _line_read(char *line);

/** Redraw the prompt
 *
 */
static inline void radmin_prompt_redraw(void)
{
	fflush(stderr);
	fflush(stdout);

	/*
	 *	Trash anything pending on the prompt...
	 */
	rl_line_buffer[0] = '\0';
	rl_end = 0;
	rl_point = 0;
	rl_forced_update_display();

	/*
	 *	Re-prompt by reinstalling the callback
	 *	This is how other projects do it too...
	 */
	rl_callback_handler_install("radmin> ", _line_read);
}

/** Read a challenge on a newly TCP connected socket, and respond
 *
 * @param[in] conn	to process the challenge on.
 * @param[in] secret	to use to formulate our response.
 * @return
 *	- -1 on failure.
 *	- 1 call again.
 *	- 0 on success.
 */
static ssize_t conn_challenge_tcp(radmin_conn_t *conn, char const *secret)
{
	size_t			ret;
	size_t			len;
	uint8_t const		*challenge;
	uint8_t			digest[MD5_DIGEST_LENGTH];
	fr_channel_type_t	channel;

	/*
	 *	When connecting over a socket, the server challenges us.
	 */
	switch (fr_channel_read(&challenge, &len, &channel, conn->fd, conn->buff)) {
	case FR_CHANNEL_STATUS_FAIL:
		ERROR("Failed to read challenge: %s", fr_strerror());
		return -1;

	case FR_CHANNEL_STATUS_AGAIN:
		return 1;

	case FR_CHANNEL_STATUS_SUCCESS:
		break;
	}

	if ((len != 16) || (channel != FR_CHANNEL_AUTH_CHALLENGE)) {
		ERROR("Failed to read challenge");
		return -1;
	}

	fr_hmac_md5(digest, (uint8_t const *)secret, strlen(secret), challenge, (size_t)len);

	ret = fr_channel_write(conn->fd, FR_CHANNEL_AUTH_RESPONSE, digest, sizeof(digest));
	if (ret <= 0) return -1;

	talloc_free(conn->secret);
	conn->secret = talloc_strdup(conn, secret);

	/*
	 *	If the server doesn't like us, it just closes the
	 *	socket.  So we don't look for an ACK.
	 */
	return ret;
}

/** Read data from all channels on a socket
 *
 * @param[in,out] conn	to read from and to store data in.
 * @return
 *	- -1 on failure.
 *	- 0 on connection failed.
 *	- +1 on OK.
 */
static fr_channel_status_t conn_channels_drain(radmin_conn_t *conn)
{
	size_t			len;
	fr_channel_type_t	channel;
	uint8_t	const		*data;
	fr_channel_status_t	status;

	for (;;) {
		uint32_t notify;

		status = fr_channel_read(&data, &len, &channel, conn->fd, conn->buff);
		switch (status) {
		case FR_CHANNEL_STATUS_FAIL:
			ERROR("%s", fr_strerror());
			/* FALL-THROUGH */

		case FR_CHANNEL_STATUS_AGAIN:
			return status;

		case FR_CHANNEL_STATUS_SUCCESS:	/* Got to do stuff... */
			break;
		}

		switch (channel) {
		case FR_CHANNEL_STDOUT:
			fprintf(stdout, "%.*s", (int)len, data);
			break;

		case FR_CHANNEL_STDERR:
			fprintf(stderr, "%.*s", (int)len, data);
			break;

		case FR_CHANNEL_CMD_STATUS:
			if (len < 4) return FR_CHANNEL_STATUS_FAIL;

			memcpy(&status, data, sizeof(status));
			status = ntohl(status);
			return status;

		case FR_CHANNEL_NOTIFY:
			if (len < 4) return FR_CHANNEL_STATUS_FAIL;

			memcpy(&notify, data, sizeof(notify));
			notify = ntohl(notify);

			/*
			 *	Switch streaming mode on/off
			 */
			if (notify == FR_NOTIFY_UNBUFFERED) state.unbuffered = true;
			else if (notify == FR_NOTIFY_BUFFERED) state.unbuffered = false;

			break;

		default:
			ERROR("Unexpected response %02x", channel);
			return FR_CHANNEL_STATUS_FAIL;
		}
	}

	/* never gets here */
}

/** (re-)run a command
 *
 * @param[in] conn	to run the command on.
 * @param[in] command	to run (may be NULL, in which case we re-run the last command);
 * @return
 *	- <= 0 on connection failure.
 *	- >0 on success (the number of bytes written to the socket).
 */
static ssize_t command_run(radmin_conn_t *conn, char const *command)
{
	ssize_t slen;

	/*
	 *	Yes, this is meant to be pointer comparison.
	 */
	if (command != conn->last_command) {
		if (state.echo) DEBUG("%s", command);

		if (conn->last_command) TALLOC_FREE(conn->last_command);
		conn->last_command = talloc_strdup(NULL, command);
	}

	/*
	 *	Write the text to the socket.
	 */
	slen = fr_channel_write(conn->fd, FR_CHANNEL_STDIN,
				conn->last_command, talloc_array_length(conn->last_command) - 1);
	if (slen <= 0) return slen;

	return slen;
}

/** Callback for readline
 *
 * Read an actual line from stdin.  Installed as a callback for readline.
 *
 * @note This is not called in batch mode, so we assume it's an interactive terminal.
 *
 * @param[in] line	readline read from stdin.
 */
static void _line_read(char *line)
{
	char		*p;
	size_t		ret;

	/*
	 *	Strip off leading spaces.
	 */
	for (p = line; *p != '\0'; p++) {
		switch (*p) {
		case ' ':
		case '\t':
			line = p + 1;
			continue;

		case '#':		/* Comment, ignore the line */
			return;

		default:
			break;
		}
		break;
	}

	/*
	 *	Strip off CR / LF
	 */
	for (p = line; *p != '\0'; p++) {
		switch (*p) {
		case '\r':
		case '\n':
			*p = '\0';
			break;

		default:
			continue;
		}
	}

	if (*line == '\0') {
		if (!state.active_conn->connected) conn_reconnect(&state.active_conn, state.active_conn->last_command);
	redraw:
		radmin_prompt_redraw();
		return;
	}

#ifdef USE_READLINE_HISTORY
	add_history(line);
#endif

	/*
	 *	Process radmin specific local commands
	 */
	if (strcmp(line, "reconnect") == 0) {
		conn_reconnect(&state.active_conn, NULL);
		goto redraw;
	}

	if (strncmp(line, "secret ", 7) == 0) {
		if (state.active_conn->type == RADMIN_CONN_TCP) {
			conn_challenge_tcp(state.active_conn, line + 7);
		} else {
			DEBUG("'secret' has no effect when connected on a unix socket");
		}
		goto redraw;
	}
	if ((strcmp(line, "exit") == 0) ||
	    (strcmp(line, "quit") == 0)) {
		fr_event_loop_exit(state.event_list, RADMIN_EVENT_LOOP_EXIT_SUCCESS);
		return;
	}

	if ((state.active_conn->type == RADMIN_CONN_TCP) && !state.active_conn->secret) {
		ERROR("You must issue 'secret <SECRET>' before running any commands");
		goto redraw;
	}

	ret = command_run(state.active_conn, line);
	if (ret > 0) return;

	if (conn_reconnect(&state.active_conn, line) < 0) {
		fr_event_loop_exit(state.event_list, EXIT_FAILURE);
		return;
	}
}

/** Process data we received on stdin
 *
 * This is a wrapper around readline's rlm_callback_read_char, which calls
 * the input callback we installed earlier.
 */
static void _event_process_stdin(UNUSED fr_event_list_t *event_list, UNUSED int fd, UNUSED void *ctx)
{
	rl_callback_read_char();
}

/** Streaming control data is available from the control socket
 *
 * This can be the response to a command, or proper streaming log messages
 * from a debug connection.
 */
static void _event_process_control(UNUSED fr_event_list_t *event_list, UNUSED int fd, void *ctx)
{
	ssize_t		ret;
	radmin_conn_t	*conn = talloc_get_type_abort(ctx, radmin_conn_t);
	radmin_conn_t	*new_conn = conn;

	ret = conn_channels_drain(conn);
	if (ret < 0) {
		/*
		 *	We got told there was data, but when we went to
		 *	read it the socket had gone away...
		 *
		 *	Reconnect, and re-issue the last command.
		 */
		if (conn_reconnect(&new_conn, conn->last_command) < 0) {
			ERROR("Failed reconnecting to server.  Hit return to retry...");
			goto finish;
		}

		/*
		 *	...and update the active connection (to the new one).
		 */
		if (state.active_conn == conn) state.active_conn = new_conn;

		/*
		 *	...and now we return (we should get called again).
		 */
		goto finish;
	}

	TALLOC_FREE(conn->last_command);	/* Clear the last command (it was successful) */

finish:
	radmin_prompt_redraw();
}

/** Close a file descriptor
 *
 * @param[in] conn to close.
 */
static int conn_close(radmin_conn_t *conn)
{
	if (conn->fd >= 0) {
		if (conn->event_list) fr_event_fd_delete(conn->event_list, 0, conn->fd);
		close(conn->fd);
		conn->fd = -1;
		conn->connected = false;
	}
	return 0;
}

/** Close the file descriptor associated with a connection
 *
 * @param[in] conn to free.
 * @return 0;
 */
static int _conn_free(radmin_conn_t *conn)
{
	conn_close(conn);
	return 0;
}

/** Common connection function for both files and sockets
 *
 * @note Don't call this function directly.
 *
 * On success, the new conn takes ownership of the fd, and will close the fd when
 * the new conn is freed.
 *
 * @param[out] out	Where to write a pointer to the new connection.
 * @param[in] fd	File descriptor to connect on.
 * @return
 *	- -1 couldn't connect to server or socket.
 *	- 0 success.
 */
static int _conn_connect(radmin_conn_t **out, int fd)
{
	ssize_t			ret;
	size_t			len;

	char			buffer[8];
	fr_channel_type_t	channel;
	uint32_t		magic;
	uint8_t	const		*data;

	radmin_conn_t		*conn;

	*out = NULL;

	MEM(conn = talloc_zero(NULL, radmin_conn_t));
	conn->fd = -1;
	talloc_set_destructor(conn, _conn_free);

	MEM(conn->buff = fr_channel_buff_alloc(conn, 1024));

	if (fr_sigpipe_disable(fd) < 0) {
		ERROR("%s", fr_strerror());
		talloc_free(conn);
		return -1;
	}

	/*
	 *	Set up the initial header data.
	 */
	magic = 0xf7eead16;
	magic = htonl(magic);
	memcpy(buffer, &magic, sizeof(magic));
	memset(buffer + sizeof(magic), 0, sizeof(magic));

	DEBUG3("Sending version check challenge");
	ret = fr_channel_write(fd, FR_CHANNEL_INIT_ACK, buffer, 8);
	if (ret <= 0) {
	error:
		ERROR("Failed writing init_ack to socket: %s", fr_syserror(errno));
		talloc_free(conn);
		return -1;
	}

	/* Blocking read */
	DEBUG3("Waiting for version check response...");
	switch (fr_channel_read(&data, &len, &channel, fd, conn->buff)) {
	case FR_CHANNEL_STATUS_SUCCESS:
		break;

	default:
		goto error;
	}

	if ((len != 8) || (channel != FR_CHANNEL_INIT_ACK) || (memcmp(data, buffer, len) != 0)) {
		ERROR("Incompatible versions");
		return -1;
	}

	DEBUG3("Version check OK");
	conn->fd = fd;
	conn->connected = true;

	*out = conn;

	return 0;
}

/** Change connection to be nonblocking
 *
 * @param[in] conn		to set as nonblocking.
 * @return
 *	- 0 on success (now non-blocking).
 *	- -1 if we couldn't change the blocking mode.
 */
static int conn_nonblock(radmin_conn_t *conn)
{
	if (fr_nonblock(conn->fd) < 0) return -1;
	conn->nonblock = true;
	return 0;
}

/** Add an event handler for this connection
 *
 * @param[in] conn		to add event handler for.
 * @param[in] event_list	to add handler to.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int conn_event_add(radmin_conn_t *conn, fr_event_list_t *event_list)
{
	if (fr_event_fd_insert(event_list, 0, conn->fd, _event_process_control, conn) < 0) {
		ERROR("%s", fr_strerror());
		return -1;
	}
	conn->event_list = event_list;

	return 0;
}

/** Connect to a UNIX socket
 *
 * @param[out] out	Where to write new connection structure.
 * @param[in] file	Unix socket to connect to.
 * @return
 *	- -1 couldn't connect to server or socket.
 *	- 0 success.
 */
static int conn_connect_unix(radmin_conn_t **out, char const *file)
{
	radmin_conn_t *conn;
	int fd;

	/*
	 *	FIXME: Get destination from command line, if possible?
	 */
	fd = fr_socket_client_unix(file, false);		/* We change to non-blocking later */
	if (fd < 0) {
		ERROR("%s", fr_strerror());
		if ((errno == ENOENT) && !state.active_conn) {	/* Not a reconnection */
			ERROR("Perhaps you need to run the commands:");
			ERROR("  cd %s", RADIUS_DIR);
			ERROR("  ln -s sites-available/control-socket sites-enabled/control-socket");
			ERROR("and/or (re-)start the server?");
		}
		return -1;
	}

	if (_conn_connect(&conn, fd) < 0) {
		close(fd);
		return -1;
	}

#ifdef SO_PEERCRED
	{
		struct ucred ucred;
		size_t len;

		if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0) {
			DEBUG("Connected to PID %u", ucred.pid);
		}
	}
#endif

	conn->server = talloc_strdup(conn, file);
	conn->type = RADMIN_CONN_UNIX;

	*out = conn;

	return 0;
}

/** Connect to a remote host
 *
 * @param[out] out	Where to write new connection structure.
 * @param[in] server	(fqdn or ip) to connect to.  Only file or server may be specified.
 * @param[in] secret	we use to authenticate ourselves to the server.
 * @return
 *	- -1 couldn't connect to server or socket.
 *	- 0 success.
 */
static int conn_connect_tcp(radmin_conn_t **out, char const *server, char const *secret)
{
	radmin_conn_t	*conn;
	int		fd;

	ssize_t		ret;

	uint16_t	port;
	fr_ipaddr_t	ipaddr;
	char		*p;

	char		*host = talloc_strdup(NULL, server);

	p = strchr(host, ':');
	if (!p) {
		port = PW_RADMIN_PORT;
	} else {
		port = atoi(p + 1);
		*p = '\0';
	}

	if (fr_inet_hton(&ipaddr, AF_INET, host, false) < 0) {
		ERROR("Failed looking up host %s: %s", host, fr_syserror(errno));
	error:
		talloc_free(host);
		return -1;
	}

	fd = fr_socket_client_tcp(NULL, &ipaddr, port, false);
	if (fd < 0) {
		ERROR("Failed opening socket %s: %s", server, fr_syserror(errno));
		goto error;
	}

	if (_conn_connect(&conn, fd) < 0) {
		close(fd);
		goto error;
	}

	conn->server = talloc_strdup(conn, server);
	conn->type = RADMIN_CONN_TCP;

	if (secret) {
		ret = conn_challenge_tcp(conn, secret);
		if (ret <= 0) {
			talloc_free(conn);	/* also closes fd */
			return -1;
		}
	}

	*out = conn;

	return 0;
}

/** (Re)connect a socket
 *
 * @param[in] conn	to reconnect (may be set to NULL if we fail).
 * @param[in] command	to (re)issue if we manage to connect.
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
static int conn_reconnect(radmin_conn_t **conn, char const *command)
{
	radmin_conn_t *new_conn;

	DEBUG("Reconnecting...");

	conn_close(*conn);

	switch (state.active_conn->type) {
	case RADMIN_CONN_UNIX:
		if (conn_connect_unix(&new_conn, (*conn)->server) < 0) {
		error:
			(*conn)->connected = false;
			return -1;
		}
		break;

	case RADMIN_CONN_TCP:
		if (conn_connect_tcp(&new_conn, (*conn)->server, (*conn)->secret) < 0) goto error;
		break;

	default:
		assert(0);
		return -1;
	}

	if ((*conn)->event_list) conn_event_add(new_conn, (*conn)->event_list);
	if ((*conn)->nonblock) conn_nonblock(new_conn);

	/*
	 *	We have to destroy the old connection, removing its
	 *	event handler, before we add the new connection.
	 */
	talloc_free(*conn);
	*conn = new_conn;

	DEBUG("...reconnected");
	if (command) command_run(*conn, command);

	return 0;
}

int main(int argc, char **argv)
{
	int		argval;

	char const	*file = NULL;
	char const	*name = "radiusd";
	char const	*input_file = NULL;
	FILE		*input_fp = stdin;
	char const	*server = NULL;
	fr_dict_t	*dict = NULL;

	char const	*radius_dir = RADIUS_DIR;
	char const	*dict_dir = DICTDIR;

	char		*commands[MAX_COMMANDS];
	int		num_commands = -1;

	TALLOC_CTX	*autofree = talloc_init("main");

	int		exit_status = EXIT_SUCCESS;

#ifndef NDEBUG
	if (fr_fault_setup(getenv("PANIC_ACTION"), argv[0]) < 0) {
		ERROR("%s", fr_strerror());
		exit(EXIT_FAILURE);
	}
#endif

	talloc_set_log_stderr();

	if ((progname = strrchr(argv[0], FR_DIR_SEP)) == NULL) {
		progname = argv[0];
	} else {
		progname++;
	}

	rad_debug_lvl = L_DBG_LVL_1;

	while ((argval = getopt(argc, argv, "d:D:hi:e:Ef:n:qs:Sx")) != EOF) {
		switch (argval) {
		case 'd':
			if (file) {
				ERROR("-d and -f cannot be used together");
				exit(EXIT_FAILURE);
			}
			if (server) {
				ERROR("-d and -s cannot be used together");
				exit(EXIT_FAILURE);
			}
			radius_dir = optarg;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'e':
			num_commands++; /* starts at -1 */
			if (num_commands >= MAX_COMMANDS) {
				ERROR("Too many '-e'");
				exit(EXIT_FAILURE);
			}
			state.batch = true;

			commands[num_commands] = optarg;
			break;

		case 'E':
			state.echo = true;
			break;

		case 'f':
			radius_dir = NULL;
			file = optarg;
			break;

		default:
		case 'h':
			usage(0);	/* never returns */

		case 'i':
			if (strcmp(optarg, "-") != 0) {
				input_file = optarg;
			}
			state.batch = true;
			break;

		case 'n':
			name = optarg;
			break;

		case 's':
			if (file) {
				ERROR("-s and -f cannot be used together");
				usage(1);
			}
			radius_dir = NULL;
			server = optarg;
			break;

		case 'S':
			//secret = NULL;
			break;

		case 'q':
			if (rad_debug_lvl > 0) rad_debug_lvl--;
			break;

		case 'x':
			rad_debug_lvl++;
			break;
		}
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		ERROR("%s", fr_strerror());
		exit(EXIT_FAILURE);
	}

	if (radius_dir) {
		int		rcode;
		CONF_SECTION	*cs, *subcs;
		uid_t		uid;
		gid_t		gid;
		char const	*uid_name = NULL;
		char const	*gid_name = NULL;
		struct passwd	*pwd;
		struct group	*grp;
		char		buffer[1024];

		file = NULL;	/* MUST read it from the conffile now */

		snprintf(buffer, sizeof(buffer), "%s/%s.conf", radius_dir, name);

		/*
		 *	Need to read in the dictionaries, else we may get
		 *	validation errors when we try and parse the config.
		 */
		if (fr_dict_from_file(autofree, &dict, dict_dir, FR_DICTIONARY_FILE, "radius") < 0) {
			ERROR("%s", fr_strerror());
			exit(64);
		}

		if (fr_dict_read(dict, radius_dir, FR_DICTIONARY_FILE) == -1) {
			ERROR("%s", fr_strerror());
			exit(64);
		}

		cs = cf_section_alloc(NULL, "main", NULL);
		if (!cs) exit(EXIT_FAILURE);

		if (cf_file_read(cs, buffer) < 0) {
			ERROR("Errors reading or parsing %s", buffer);
			talloc_free(cs);
			usage(1);
		}

		uid = getuid();
		gid = getgid();

		subcs = NULL;
		while ((subcs = cf_subsection_find_next(cs, subcs, "listen")) != NULL) {
			char const *value;
			CONF_PAIR *cp = cf_pair_find(subcs, "type");

			if (!cp) continue;

			value = cf_pair_value(cp);
			if (!value) continue;

			if (strcmp(value, "control") != 0) continue;

			/*
			 *	Now find the socket name (sigh)
			 */
			rcode = cf_pair_parse(subcs, "socket",
					      FR_ITEM_POINTER(PW_TYPE_STRING, &file), NULL, T_DOUBLE_QUOTED_STRING);
			if (rcode < 0) {
				ERROR("Failed parsing listen section 'socket'");
				exit(EXIT_FAILURE);
			}

			if (!file) {
				ERROR("No path given for socket");
				usage(1);
			}

			/*
			 *	If we're root, just use the first one we find
			 */
			if (uid == 0) break;

			/*
			 *	Check UID and GID.
			 */
			rcode = cf_pair_parse(subcs, "uid",
					      FR_ITEM_POINTER(PW_TYPE_STRING, &uid_name), NULL, T_DOUBLE_QUOTED_STRING);
			if (rcode < 0) {
				ERROR("Failed parsing listen section 'uid'");
				exit(EXIT_FAILURE);
			}

			if (!uid_name) break;

			pwd = getpwnam(uid_name);
			if (!pwd) {
				ERROR("Failed getting UID for user %s: %s", uid_name, strerror(errno));
				exit(EXIT_FAILURE);
			}

			if (uid != pwd->pw_uid) continue;

			rcode = cf_pair_parse(subcs, "gid",
					      FR_ITEM_POINTER(PW_TYPE_STRING, &gid_name), NULL, T_DOUBLE_QUOTED_STRING);
			if (rcode < 0) {
				ERROR("Failed parsing listen section 'gid'");
				exit(EXIT_FAILURE);
			}

			if (!gid_name) break;

			grp = getgrnam(gid_name);
			if (!grp) {
				ERROR("Failed resolving gid of group %s: %s", gid_name, strerror(errno));
				exit(EXIT_FAILURE);
			}

			if (gid != grp->gr_gid) continue;

			break;
		}

		if (!file) {
			ERROR("Could not find control socket in %s", buffer);
			exit(EXIT_FAILURE);
		}
	}

/*
	if (input_file) {
		input_fp = fopen(input_file, "r");
		if (!input_fp) {
			ERROR("Failed opening %s: %s", input_file, fr_syserror(errno));
			exit(EXIT_FAILURE);
		}
	}
*/

	if ((!file && !server) || (file && server)) {
		ERROR("Must use one of '-d' or '-f' or '-s'");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Check if stdin is a TTY only if input is from stdin
	 */
	if (input_file && !state.batch && !isatty(STDIN_FILENO)) state.batch = true;

	if (!state.batch) {
#ifdef USE_READLINE_HISTORY
		using_history();
#endif
		rl_bind_key('\t', rl_insert);
	}

	/*
	 *	Prevent SIGPIPEs from terminating the process
	 */
	signal(SIGPIPE, SIG_IGN);

	/*
	 *	Connect to the server
	 */
	if (server) {
		if (conn_connect_tcp(&state.active_conn, server, NULL) < 0) exit(EXIT_FAILURE);
	} else if (file) {
		if (conn_connect_unix(&state.active_conn, file) < 0) exit(EXIT_FAILURE);
	} else {
		exit(EXIT_FAILURE);
	}

	/*
	 *	Run commands from the command-line (non-interactively).
	 */
	if (num_commands >= 0) {
		ssize_t ret;
		int i;

		for (i = 0; i <= num_commands; i++) {
			/* Write the command */
			ret = command_run(state.active_conn, commands[i]);
			if (ret <= 0) exit(EXIT_FAILURE);

			/* Read the response */
			if (ret > 0) {
				ret = conn_channels_drain(state.active_conn);
				if (ret < 0) exit(EXIT_FAILURE);
			}

			if (ret == FR_CHANNEL_STATUS_FAIL) {
				goto finish;
				exit_status = EXIT_FAILURE;
			}
		}

		/*
		 *	One of the commands requires us to do a blocking
		 *	read until we're told to exit.
		 *
		 *	Probably non-interactive streaming debug.
		 */
		if (state.unbuffered) while (true) conn_channels_drain(state.active_conn);
	/*
	 *	Run commands from the user (interactively)
	 */
	} else {
		DEBUG("%s", radmin_version);
		DEBUG("FreeRADIUS Server administration tool.");
		DEBUG("Copyright (C) 2008-2016 The FreeRADIUS server project and contributors.");
		DEBUG("There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A.");
		DEBUG("PARTICULAR PURPOSE.");
		DEBUG("You may redistribute copies of FreeRADIUS under the terms of the.");
		DEBUG("GNU General Public License v2.");

		rl_callback_handler_install("radmin> ", _line_read);
		radmin_prompt_redraw();

		/* Install handler for stdin */
		MEM(state.event_list = fr_event_list_create(autofree, NULL));
		if (fr_event_fd_insert(state.event_list, 0, fileno(stdin), _event_process_stdin, NULL) < 0) {
			ERROR("%s", fr_strerror());
			exit(EXIT_FAILURE);
		}
		conn_event_add(state.active_conn, state.event_list);
		conn_nonblock(state.active_conn);

		/* Enter the event loop */
		exit_status = fr_event_loop(state.event_list);

		/* Event loop needs a non-zero exit status value to actually exit */
		if (exit_status == RADMIN_EVENT_LOOP_EXIT_SUCCESS) exit_status = 0;
		rl_callback_handler_remove();
 	}
finish:
	if (input_fp != stdin) fclose(input_fp);

	talloc_free(autofree);

	return exit_status;
}
