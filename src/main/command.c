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
 * @file command.c
 *
 * @brief Commands available via the control socket
 *
 * @copyright 2008,2016 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok <aland@deployingradius.com>
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <sys/stat.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/channel.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/command.h>
#include <freeradius-devel/control.h>
#include <freeradius-devel/detail.h>
#include <freeradius-devel/state.h>

#ifdef HAVE_GPERFTOOLS_PROFILER_H
#  include <gperftools/profiler.h>
#endif

#define CMD_FAIL FR_CHANNEL_STATUS_FAIL
#define CMD_OK   FR_CHANNEL_STATUS_SUCCESS

static char debug_log_file_buffer[1024];

static int command_hup(rad_listen_t *listen, int argc, char *argv[])
{
	CONF_SECTION *cs;
	module_instance_t *instance;
	char buffer[256];

	if (argc == 0) {
		radius_signal_self(RADIUS_SIGNAL_SELF_HUP);
		return CMD_OK;
	}

	/*
	 *	Hack a "main" HUP thingy
	 */
	if (strcmp(argv[0], "main.log") == 0) {
		hup_logfile();
		return CMD_OK;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return CMD_FAIL;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		control_printf_error(listen, "No such module \"%s\"\n", argv[0]);
		return CMD_FAIL;
	}

	if ((instance->module->type & RLM_TYPE_HUP_SAFE) == 0) {
		control_printf_error(listen, "Module %s cannot be hup'd\n",
			argv[0]);
		return CMD_FAIL;
	}

	if (!module_hup(instance->cs, instance, time(NULL))) {
		control_printf_error(listen, "Failed to reload module\n");
		return CMD_FAIL;
	}

	snprintf(buffer, sizeof(buffer), "modules.%s.hup",
		 cf_section_name1(instance->cs));
	trigger_exec(NULL, instance->cs, buffer, true, NULL);

	return CMD_OK;
}

static int command_terminate(UNUSED rad_listen_t *listen,
			     UNUSED int argc, UNUSED char *argv[])
{
	radius_signal_self(RADIUS_SIGNAL_SELF_TERM);

	return CMD_OK;
}

static int command_uptime(rad_listen_t *listen,
			  UNUSED int argc, UNUSED char *argv[])
{
	char buffer[128];

	CTIME_R(&fr_start_time, buffer, sizeof(buffer));
	control_printf(listen, "Up since %s", buffer); /* no \r\n */

	return CMD_OK;
}

static int command_show_config(rad_listen_t *listen, int argc, char *argv[])
{
	CONF_ITEM *ci;
	CONF_PAIR *cp;
	char const *value;

	if (argc != 1) {
		control_printf_error(listen, "No path was given\n");
		return CMD_FAIL;
	}

	ci = cf_reference_item(main_config.config, main_config.config, argv[0]);
	if (!ci) return CMD_FAIL;

	if (!cf_item_is_pair(ci)) return CMD_FAIL;

	cp = cf_item_to_pair(ci);
	value = cf_pair_value(cp);
	if (!value) return CMD_FAIL;

	control_printf(listen, "%s\n", value);

	return CMD_OK;
}

static char const tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

/*
 *	FIXME: Recurse && indent?
 */
static void cprint_conf_parser(rad_listen_t *listen, int indent, CONF_SECTION *cs,
			       void const *base)

{
	int i;
	char const *name1 = cf_section_name1(cs);
	char const *name2 = cf_section_name2(cs);
	CONF_PARSER const *variables = cf_section_parse_table(cs);

	if (name2) {
		control_printf(listen, "%.*s%s %s {\n", indent, tabs, name1, name2);
	} else {
		control_printf(listen, "%.*s%s {\n", indent, tabs, name1);
	}

	indent++;

	/*
	 *	Print
	 */
	if (variables) for (i = 0; variables[i].name != NULL; i++) {
		void const *data;
		char buffer[INET6_ADDRSTRLEN];

		/*
		 *	No base struct offset, data must be the pointer.
		 *	If data doesn't exist, ignore the entry, there
		 *	must be something wrong.
		 */
		if (!base) {
			if (!variables[i].data) {
				continue;
			}

			data = variables[i].data;

		} else if (variables[i].data) {
			data = variables[i].data;

		} else {
			data = (((char const *)base) + variables[i].offset);
		}

		/*
		 *	Ignore the various flags
		 */
		switch (variables[i].type & 0xff) {
		default:
			control_printf(listen, "%.*s%s = ?\n", indent, tabs,
				variables[i].name);
			break;

		case PW_TYPE_INTEGER:
			control_printf(listen, "%.*s%s = %u\n", indent, tabs,
				variables[i].name, *(int const *) data);
			break;

		case PW_TYPE_IPV4_ADDR:
			inet_ntop(AF_INET, data, buffer, sizeof(buffer));
			break;

		case PW_TYPE_IPV6_ADDR:
			inet_ntop(AF_INET6, data, buffer, sizeof(buffer));
			break;

		case PW_TYPE_BOOLEAN:
			control_printf(listen, "%.*s%s = %s\n", indent, tabs,
				variables[i].name,
				((*(bool const *) data) == false) ? "no" : "yes");
			break;

		case PW_TYPE_STRING:
		case PW_TYPE_FILE_INPUT:
		case PW_TYPE_FILE_OUTPUT:
			/*
			 *	FIXME: Escape things in the string!
			 */
			if (*(char const * const *) data) {
				control_printf(listen, "%.*s%s = \"%s\"\n", indent, tabs,
					variables[i].name, *(char const * const *) data);
			} else {
				control_printf(listen, "%.*s%s = \n", indent, tabs,
					variables[i].name);
			}

			break;
		}
	}

	indent--;

	control_printf(listen, "%.*s}\n", indent, tabs);
}

static int command_show_module_config(rad_listen_t *listen, int argc, char *argv[])
{
	CONF_SECTION *cs;
	module_instance_t *instance;

	if (argc != 1) {
		control_printf_error(listen, "No module name was given\n");
		return CMD_FAIL;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return CMD_FAIL;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		control_printf_error(listen, "No such module \"%s\"\n", argv[0]);
		return CMD_FAIL;
	}

	cprint_conf_parser(listen, 0, instance->cs, instance->data);

	return CMD_OK;
}

static char const *method_names[MOD_COUNT] = {
	"authenticate",
	"authorize",
	"preacct",
	"accounting",
	"session",
	"pre-proxy",
	"post-proxy",
	"post-auth"
};


static int command_show_module_methods(rad_listen_t *listen, int argc, char *argv[])
{
	int i;
	CONF_SECTION *cs;
	module_instance_t const *instance;

	if (argc != 1) {
		control_printf_error(listen, "No module name was given\n");
		return CMD_FAIL;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return CMD_FAIL;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		control_printf_error(listen, "No such module \"%s\"\n", argv[0]);
		return CMD_FAIL;
	}

	for (i = 0; i < MOD_COUNT; i++) {
		if (instance->module->methods[i]) control_printf(listen, "%s\n", method_names[i]);
	}

	return CMD_OK;
}


static int command_show_module_flags(rad_listen_t *listen, int argc, char *argv[])
{
	CONF_SECTION *cs;
	module_instance_t const *instance;

	if (argc != 1) {
		control_printf_error(listen, "No module name was given\n");
		return CMD_FAIL;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return CMD_FAIL;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		control_printf_error(listen, "No such module \"%s\"\n", argv[0]);
		return CMD_FAIL;
	}

	if ((instance->module->type & RLM_TYPE_THREAD_UNSAFE) != 0) control_printf(listen, "thread-unsafe\n");

	if ((instance->module->type & RLM_TYPE_HUP_SAFE) != 0) control_printf(listen, "reload-on-hup\n");

	return CMD_OK;
}

static int command_show_module_status(rad_listen_t *listen, int argc, char *argv[])
{
	CONF_SECTION *cs;
	const module_instance_t *instance;

	if (argc != 1) {
		control_printf_error(listen, "No module name was given\n");
		return CMD_FAIL;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return CMD_FAIL;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		control_printf_error(listen, "No such module \"%s\"\n", argv[0]);
		return CMD_FAIL;
	}

	if (!instance->force) {
		control_printf(listen, "alive\n");
	} else {
		control_printf(listen, "%s\n", fr_int2str(mod_rcode_table, instance->code, "<invalid>"));
	}


	return CMD_OK;
}


/*
 *	Show all loaded modules
 */
static int command_show_modules(rad_listen_t *listen, UNUSED int argc, UNUSED char *argv[])
{
	CONF_SECTION *cs, *subcs;

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return CMD_FAIL;

	subcs = NULL;
	while ((subcs = cf_subsection_find_next(cs, subcs, NULL)) != NULL) {
		char const *name1 = cf_section_name1(subcs);
		char const *name2 = cf_section_name2(subcs);

		module_instance_t *instance;

		if (name2) {
			instance = module_find(cs, name2);
			if (!instance) continue;

			control_printf(listen, "%s (%s)\n", name2, name1);
		} else {
			instance = module_find(cs, name1);
			if (!instance) continue;

			control_printf(listen, "%s\n", name1);
		}
	}

	return CMD_OK;
}

#ifdef WITH_PROXY
static int command_show_home_servers(rad_listen_t *listen, UNUSED int argc, UNUSED char *argv[])
{
	int i;
	home_server_t *home;
	char const *type, *state, *proto;

	char buffer[INET6_ADDRSTRLEN];

	for (i = 0; i < 256; i++) {
		home = home_server_bynumber(i);
		if (!home) break;

		/*
		 *	Internal "virtual" home server.
		 */
		if (home->ipaddr.af == AF_UNSPEC) continue;

		if (home->type == HOME_TYPE_AUTH) {
			type = "auth";

		} else if (home->type == HOME_TYPE_ACCT) {
			type = "acct";

		} else if (home->type == HOME_TYPE_AUTH_ACCT) {
			type = "auth+acct";

#ifdef WITH_COA
		} else if (home->type == HOME_TYPE_COA) {
			type = "coa";
#endif

		} else continue;

		if (home->proto == IPPROTO_UDP) {
			proto = "udp";
		}
#ifdef WITH_TCP
		else if (home->proto == IPPROTO_TCP) {
			proto = "tcp";
		}
#endif
		else proto = "??";

		if (home->state == HOME_STATE_ALIVE) {
			state = "alive";

		} else if (home->state == HOME_STATE_ZOMBIE) {
			state = "zombie";

		} else if (home->state == HOME_STATE_IS_DEAD) {
			state = "dead";

		} else if (home->state == HOME_STATE_UNKNOWN) {
			time_t now = time(NULL);

			/*
			 *	We've recently received a packet, so
			 *	the home server seems to be alive.
			 *
			 *	The *reported* state changes because
			 *	the internal state machine NEEDS THE
			 *	RIGHT STATE.  However, reporting that
			 *	to the admin will confuse them.
			 *	So... we lie.  No, that dress doesn't
			 *	make you look fat...
			 */
			if ((home->last_packet_recv + (int)home->ping_interval) >= now) {
				state = "alive";
			} else {
				state = "unknown";
			}

		} else continue;

		control_printf(listen, "%s\t%s\t%d\t%s\t%s\t%s\t%d\n",
			fr_inet_ntoh(&home->ipaddr, buffer, sizeof(buffer)),
			home->name, home->port, proto, type, state,
			home->currently_outstanding);
	}

	return CMD_OK;
}
#endif

static int command_show_clients(rad_listen_t *listen, UNUSED int argc, UNUSED char *argv[])
{
	int i;
	RADCLIENT *client;
	char buffer[256];
	char ipaddr[256];

	for (i = 0; i < 256; i++) {
		client = client_findbynumber(NULL, i);
		if (!client) break;

		fr_inet_ntoh(&client->ipaddr, buffer, sizeof(buffer));

		if (((client->ipaddr.af == AF_INET) &&
		     (client->ipaddr.prefix != 32)) ||
		    ((client->ipaddr.af == AF_INET6) &&
		     (client->ipaddr.prefix != 128))) {
			snprintf(ipaddr, sizeof(ipaddr), "%s/%d", buffer, client->ipaddr.prefix);
		} else {
			snprintf(ipaddr, sizeof(ipaddr), "%s", buffer);
		}

		control_printf(listen, "%s\t%s\t%s\t%s\n", ipaddr,
			client->shortname ? client->shortname : "\t",
			client->nas_type ? client->nas_type : "\t",
			client->server ? client->server : "\t");
	}

	return CMD_OK;
}


static int command_show_version(rad_listen_t *listen, UNUSED int argc, UNUSED char *argv[])
{
	control_printf(listen, "%s\n", radiusd_version);
	return CMD_OK;
}

static int command_debug_level_global(rad_listen_t *listen, int argc, char *argv[])
{
	int number;

	if (argc == 0) {
		control_printf_error(listen, "Must specify <number>\n");
		return -1;
	}

	number = atoi(argv[0]);
	if ((number < 0) || (number > 4)) {
		control_printf_error(listen, "<number> must be between 0 and 4\n");
		return -1;
	}

	INFO("Global debug level set to %i, was %i", number, fr_debug_lvl);
	fr_debug_lvl = rad_debug_lvl = number;

	return CMD_OK;
}

static int command_debug_level_request(rad_listen_t *listen, int argc, char *argv[])
{
	int number;

	if (argc == 0) {
		control_printf_error(listen, "Must specify <number>\n");
		return -1;
	}

	number = atoi(argv[0]);
	if ((number < 0) || (number > 4)) {
		control_printf_error(listen, "<number> must be between 0 and 4\n");
		return -1;
	}

	INFO("Request debug level set to %i, was %i", number, req_debug_lvl);
	req_debug_lvl = number;

	return CMD_OK;
}

/** Turn off all debugging.  But don't touch the debug condition
 *
 */
static void command_debug_off(void)
{
	debug_log.dst = L_DST_NULL;
	debug_log.file = NULL;
	debug_log.cookie = NULL;
	debug_log.cookie_write = NULL;
}

#if defined(HAVE_FOPENCOOKIE) || defined (HAVE_FUNOPEN)
static pthread_mutex_t debug_mutex = PTHREAD_MUTEX_INITIALIZER;

/** Callback for log.c, so that we can write debug output to the radmin socket.
 *
 * We only have one debug condition, so we only need one mutex.
 *
 * FOPENCOOKIE  - Is the linux facility which allows callbacks to be
 *		  bound to streams.
 * FUNOPEN	- Does similar things but for BSDs.
 *
 * @param[in] cookie	The context we passed when we registered the callback.
 * @param[in] buffer	Data that was written to the stream we're listening on.
 * @param[in] len	Length of data in the buffer.
 * @return
 *	- <0 an error occurred.
 *	- >= 0 the amount of data processed.
 */
#ifdef HAVE_FOPENCOOKIE
static ssize_t _command_socket_write_debug(void *cookie, char const *buffer, size_t len)
#else
static int _command_socket_write_debug(void *cookie, char const *buffer, int len)
#endif
{
	ssize_t r;
	rad_listen_t *listen = talloc_get_type_abort(cookie, rad_listen_t);

	if (listen->status == RAD_LISTEN_STATUS_EOL) return 0;

	pthread_mutex_lock(&debug_mutex);
	r = fr_channel_write(listen->fd, FR_CHANNEL_STDOUT, buffer, len);
	pthread_mutex_unlock(&debug_mutex);

	if (r <= 0) {
		command_debug_off();
		control_close_socket(listen);
	}

	return r;
}

static int command_debug_socket(rad_listen_t *listen, int argc, char *argv[])
{
	uint32_t notify;

	if (rad_debug_lvl && default_log.dst == L_DST_STDOUT) {
		control_printf_error(listen, "Cannot redirect debug logs to a socket when already in debugging mode.\n");
		return -1;
	}

	if ((argc == 0) || (strcmp(argv[0], "off") == 0)) {
		notify = htonl(FR_NOTIFY_BUFFERED);

		/*
		 *	Tell radmin to go into buffered mode.
		 */
		(void) fr_channel_write(listen->fd, FR_CHANNEL_NOTIFY, &notify, sizeof(notify));

		command_debug_off();
		return CMD_OK;
	}

	if (strcmp(argv[0], "on") != 0) {
		control_printf_error(listen, "Syntax error: got '%s', expected [on|off]", argv[0]);
		return -1;
	}

	/*
	 *	Don't allow people to stomp on each other.
	 */
	if ((debug_log.cookie != NULL) &&
	    (debug_log.cookie != listen)) {
		control_printf_error(listen, "ERROR: Someone else is already using the debug socket");
		return -1;
	}

	/*
	 *	Disable logging while we're mucking with the buffer.
	 */
	command_debug_off();

	debug_log.cookie = listen;
	debug_log.cookie_write = _command_socket_write_debug;
	debug_log.dst = L_DST_EXTRA;

	notify = htonl(FR_NOTIFY_UNBUFFERED);

	/*
	 *	Tell radmin to go into unbuffered mode.
	 */
	(void) fr_channel_write(listen->fd, FR_CHANNEL_NOTIFY, &notify, sizeof(notify));

	return CMD_OK;
}
#endif

static int command_debug_file(rad_listen_t *listen, int argc, char *argv[])
{
	if (rad_debug_lvl && default_log.dst == L_DST_STDOUT) {
		control_printf_error(listen, "Cannot redirect debug logs to a file when already in debugging mode.\n");
		return -1;
	}

	if ((argc > 0) && (strchr(argv[0], FR_DIR_SEP) != NULL)) {
		control_printf_error(listen, "Cannot direct debug logs to absolute path.\n");
		return -1;
	}

	if (argc == 0) {
		command_debug_off();
		return CMD_OK;
	}

	/*
	 *	Disable logging while we're mucking with the buffer.
	 */
	command_debug_off();

	/*
	 *	This looks weird, but it's here to avoid locking
	 *	a mutex for every log message.
	 */
	memset(debug_log_file_buffer, 0, sizeof(debug_log_file_buffer));

	/*
	 *	Debug files always go to the logging directory.
	 */
	snprintf(debug_log_file_buffer, sizeof(debug_log_file_buffer),
		 "%s/%s", radlog_dir, argv[0]);

	debug_log.file = &debug_log_file_buffer[0];
	debug_log.dst = L_DST_FILES;

	INFO("Global debug log set to \"%s\"", debug_log.file);

	return CMD_OK;
}

static int command_debug_condition(rad_listen_t *listen, int argc, char *argv[])
{
	int i;
	char const *error;
	ssize_t slen = 0;
	fr_cond_t *new_condition = NULL;
	char *p, buffer[1024];

	/*
	 *	Disable it.
	 */
	if (argc == 0) {
		TALLOC_FREE(debug_condition);
		debug_condition = NULL;
		return CMD_OK;
	}

	if (!((argc == 1) &&
	      ((argv[0][0] == '"') || (argv[0][0] == '\'')))) {
		p = buffer;
		*p = '\0';
		for (i = 0; i < argc; i++) {
			size_t len;

			len = strlcpy(p, argv[i], buffer + sizeof(buffer) - p);
			p += len;
			*(p++) = ' ';
			*p = '\0';
		}

	} else {
		/*
		 *	Backwards compatibility.  De-escape the string.
		 */
		char quote;
		char *q;

		p = argv[0];
		q = buffer;

		quote = *(p++);

		while (true) {
			if (!*p) {
				error = "Unexpected end of string";
				slen = -strlen(argv[0]);
				p = argv[0];

				goto parse_error;
			}

			if (*p == quote) {
				if (p[1]) {
					error = "Unexpected text after end of string";
					slen = -(p - argv[0]);
					p = argv[0];

					goto parse_error;
				}
				*q = '\0';
				break;
			}

			if (*p == '\\') {
				*(q++) = p[1];
				p += 2;
				continue;
			}

			*(q++) = *(p++);
		}
	}

	p = buffer;

	slen = fr_condition_tokenize(NULL, NULL, p, &new_condition, &error, FR_COND_ONE_PASS);
	if (slen <= 0) {
		char *spaces, *text;

	parse_error:
		fr_canonicalize_error(NULL, &spaces, &text, slen, p);

		ERROR("Parse error in condition");
		ERROR("%s", p);
		ERROR("%s^ %s", spaces, error);

		control_printf_error(listen, "Parse error in condition \"%s\": %s\n", p, error);

		talloc_free(spaces);
		talloc_free(text);
		return CMD_FAIL;
	}

	/*
	 *	Delete old condition.
	 *
	 *	This is thread-safe because the condition is evaluated
	 *	in the main server thread, along with this code.
	 */
	TALLOC_FREE(debug_condition);
	debug_condition = new_condition;

	return CMD_OK;
}

#ifdef HAVE_GPERFTOOLS_PROFILER_H
static char profiler_log_buffer[1024];
/** Start the gperftools profiler
 *
 */
static int command_profiler_cpu_start(rad_listen_t *listen, int argc, char *argv[])
{
	struct ProfilerState state;

	ProfilerGetCurrentState(&state);

	if (argc == 0) {
		control_printf_error(listen, "Need filename for profiler to write to.\n");
		return -1;
	}

	if ((argc > 0) && (strchr(argv[0], FR_DIR_SEP) != NULL)) {
		control_printf_error(listen, "Profiler file must be a relative path.\n");
		return -1;
	}

	/*
	 *	We get an error if we don't stop the current
	 *	profiler first.
	 */
	if (state.enabled) {
		ProfilerFlush();
		ProfilerStop();
	}

	/*
	 *	Profiler files always go to the logging directory.
	 */
	snprintf(profiler_log_buffer, sizeof(profiler_log_buffer),
		 "%s/%s", radlog_dir, argv[0]);

	errno = 0;
	if (ProfilerStart(profiler_log_buffer) == 0) {
		control_printf_error(listen, "Failed enabling profiler: %s\n",
			      errno ? fr_syserror(errno) : "unknown error");
		return -1;
	}

	return CMD_OK;
}

/** Stop the gperftools cpu profiler
 *
 */
static int command_profiler_cpu_stop(UNUSED rad_listen_t *listen, UNUSED int argc, UNUSED char *argv[])
{
	ProfilerFlush();
	ProfilerStop();

	return CMD_OK;
}

/** Show gperftools cpu profiler output file
 *
 */
static int command_profiler_cpu_show_file(rad_listen_t *listen, UNUSED int argc, UNUSED char *argv[])
{
	struct ProfilerState state;

	ProfilerGetCurrentState(&state);

	if (!state.enabled) {
		control_printf_error(listen, "Profiler not enabled.\n");
		return -1;
	}

	control_printf(listen, "%s\n", state.profile_name);

	return CMD_OK;
}

/** Show gperftools cpu profiler samples collected
 *
 */
static int command_profiler_cpu_show_samples(rad_listen_t *listen, UNUSED int argc, UNUSED char *argv[])
{
	struct ProfilerState state;

	ProfilerGetCurrentState(&state);

	if (!state.enabled) {
		control_printf_error(listen, "Profiler not enabled.\n");
		return -1;
	}

	control_printf(listen, "%i\n", state.samples_gathered);

	return CMD_OK;
}

/** Show gperftools cpu profiler start_time
 *
 */
static int command_profiler_cpu_show_start_time(rad_listen_t *listen, UNUSED int argc, UNUSED char *argv[])
{
	char buffer[128];
	struct ProfilerState state;

	ProfilerGetCurrentState(&state);

	if (!state.enabled) {
		control_printf_error(listen, "Profiler not enabled.\n");
		return -1;
	}

	CTIME_R(&state.start_time, buffer, sizeof(buffer));
	control_printf(listen, "%s", buffer);

	return CMD_OK;
}

/** Show gperftools cpu profiler status
 *
 */
static int command_profiler_cpu_show_status(rad_listen_t *listen, UNUSED int argc, UNUSED char *argv[])
{
	struct ProfilerState state;

	ProfilerGetCurrentState(&state);

	if (state.enabled) {
		control_printf(listen, "running\n");
	} else {
		control_printf(listen, "stopped\n");
	}

	return CMD_OK;
}
#endif

static int command_show_debug_condition(rad_listen_t *listen,
					UNUSED int argc, UNUSED char *argv[])
{
	char buffer[1024];

	if (!debug_condition) {
		control_printf(listen, "\n");
		return CMD_OK;
	}

	fr_cond_snprint(buffer, sizeof(buffer), debug_condition);

	control_printf(listen, "%s\n", buffer);
	return CMD_OK;
}


static int command_show_debug_file(rad_listen_t *listen,
					UNUSED int argc, UNUSED char *argv[])
{
	if (!debug_log.file) return CMD_FAIL;

	control_printf(listen, "%s\n", debug_log.file);
	return CMD_OK;
}


static int command_show_debug_level_global(rad_listen_t *listen,
					   UNUSED int argc, UNUSED char *argv[])
{
	control_printf(listen, "%d\n", rad_debug_lvl);
	return CMD_OK;
}

static int command_show_debug_level_request(rad_listen_t *listen,
					    UNUSED int argc, UNUSED char *argv[])
{
	control_printf(listen, "%d\n", req_debug_lvl);
	return CMD_OK;
}

static RADCLIENT *get_client(rad_listen_t *listen, int argc, char *argv[])
{
	RADCLIENT *client;
	fr_ipaddr_t ipaddr;
	int myarg;
	int proto = IPPROTO_UDP;
	RADCLIENT_LIST *list = NULL;

	if (argc < 1) {
		control_printf_error(listen, "Must specify <ipaddr>\n");
		return NULL;
	}

	/*
	 *	First arg is IP address.
	 */
	if (fr_inet_hton(&ipaddr, AF_UNSPEC, argv[0], false) < 0) {
		control_printf_error(listen, "Failed parsing IP address; %s\n",
			fr_strerror());
		return NULL;
	}
	myarg = 1;

	while (myarg < argc) {
		if (strcmp(argv[myarg], "udp") == 0) {
			proto = IPPROTO_UDP;
			myarg++;
			continue;
		}

#ifdef WITH_TCP
		if (strcmp(argv[myarg], "tcp") == 0) {
			proto = IPPROTO_TCP;
			myarg++;
			continue;
		}
#endif

		if (strcmp(argv[myarg], "listen") == 0) {
			uint16_t server_port;
			fr_ipaddr_t server_ipaddr;

			if ((argc - myarg) < 2) {
				control_printf_error(listen, "Must specify listen <ipaddr> <port>\n");
				return NULL;
			}

			if (fr_inet_hton(&server_ipaddr, ipaddr.af, argv[myarg + 1], false) < 0) {
				control_printf_error(listen, "Failed parsing IP address; %s\n",
					      fr_strerror());
				return NULL;
			}

			server_port = atoi(argv[myarg + 2]);

			list = listener_find_client_list(&server_ipaddr, server_port, proto);
			if (!list) {
				control_printf_error(listen, "No such listen %s %s\n", argv[myarg + 1], argv[myarg + 2]);
				return NULL;
			}
			myarg += 3;
			continue;
		}

		control_printf_error(listen, "Unknown argument %s.\n", argv[myarg]);
		return NULL;
	}

	client = client_find(list, &ipaddr, proto);
	if (!client) {
		control_printf_error(listen, "No such client\n");
		return NULL;
	}

	return client;
}

#ifdef WITH_PROXY
static home_server_t *get_home_server(rad_listen_t *listen, int argc,
				    char *argv[], int *last)
{
	int myarg;
	home_server_t *home;
	uint16_t port;
	int proto = IPPROTO_UDP;
	fr_ipaddr_t ipaddr;

	if (argc < 2) {
		control_printf_error(listen, "Must specify <ipaddr> <port> [udp|tcp]\n");
		return NULL;
	}

	if (fr_inet_hton(&ipaddr, AF_UNSPEC, argv[0], false) < 0) {
		control_printf_error(listen, "Failed parsing IP address; %s\n",
			fr_strerror());
		return NULL;
	}

	port = atoi(argv[1]);

	myarg = 2;

	while (myarg < argc) {
		if (strcmp(argv[myarg], "udp") == 0) {
			proto = IPPROTO_UDP;
			myarg++;
			continue;
		}

#ifdef WITH_TCP
		if (strcmp(argv[myarg], "tcp") == 0) {
			proto = IPPROTO_TCP;
			myarg++;
			continue;
		}
#endif

		/*
		 *	Unknown argument.  Leave it for the caller.
		 */
		break;
	}

	home = home_server_find(&ipaddr, port, proto);
	if (!home) {
		control_printf_error(listen, "No such home server\n");
		return NULL;
	}

	if (last) *last = myarg;

	return home;
}

static int command_set_home_server_state(rad_listen_t *listen, int argc, char *argv[])
{
	int last;
	home_server_t *home;

	if (argc < 3) {
		control_printf_error(listen, "Must specify <ipaddr> <port> [udp|tcp] <state>\n");
		return CMD_FAIL;
	}

	home = get_home_server(listen, argc, argv, &last);
	if (!home) {
		return CMD_FAIL;
	}

	if (strcmp(argv[last], "alive") == 0) {
		revive_home_server(home, NULL);

	} else if (strcmp(argv[last], "dead") == 0) {
		struct timeval now;

		gettimeofday(&now, NULL); /* we do this WAY too ofetn */
		mark_home_server_dead(home, &now);

	} else {
		control_printf_error(listen, "Unknown state \"%s\"\n", argv[last]);
		return CMD_FAIL;
	}

	return CMD_OK;
}

static int command_show_home_server_state(rad_listen_t *listen, int argc, char *argv[])
{
	home_server_t *home;

	home = get_home_server(listen, argc, argv, NULL);
	if (!home) return CMD_FAIL;

	switch (home->state) {
	case HOME_STATE_ALIVE:
		control_printf(listen, "alive\n");
		break;

	case HOME_STATE_IS_DEAD:
		control_printf(listen, "dead\n");
		break;

	case HOME_STATE_ZOMBIE:
		control_printf(listen, "zombie\n");
		break;

	case HOME_STATE_UNKNOWN:
		control_printf(listen, "unknown\n");
		break;

	default:
		control_printf(listen, "invalid\n");
		break;
	}

	return CMD_OK;
}
#endif

static rad_listen_t *get_socket(rad_listen_t *listen, int argc,
			       char *argv[], int *last)
{
	rad_listen_t *sock;
	uint16_t port;
	int proto = IPPROTO_UDP;
	fr_ipaddr_t ipaddr;

	if (argc < 2) {
		control_printf_error(listen, "Must specify <ipaddr> <port> [udp|tcp]\n");
		return NULL;
	}

	if (fr_inet_hton(&ipaddr, AF_UNSPEC, argv[0], false) < 0) {
		control_printf_error(listen, "Failed parsing IP address; %s\n",
			fr_strerror());
		return NULL;
	}

	port = atoi(argv[1]);

	if (last) *last = 2;
	if (argc > 2) {
		if (strcmp(argv[2], "udp") == 0) {
			proto = IPPROTO_UDP;
			if (last) *last = 3;
		}
#ifdef WITH_TCP
		if (strcmp(argv[2], "tcp") == 0) {
			proto = IPPROTO_TCP;
			if (last) *last = 3;
		}
#endif
	}

	sock = listener_find_byipaddr(&ipaddr, port, proto);
	if (!sock) {
		control_printf_error(listen, "No such listen section\n");
		return NULL;
	}

	return sock;
}

static int command_inject_to(rad_listen_t *listen, int argc, char *argv[])
{
	fr_command_socket_t *sock = listen->data;
	listen_socket_t *data;
	rad_listen_t *found;

	found = get_socket(listen, argc, argv, NULL);
	if (!found) {
		return 0;
	}

	data = found->data;
	sock->inject_listen = found;
	sock->dst_ipaddr = data->my_ipaddr;
	sock->dst_port = data->my_port;

	return CMD_OK;
}

static int command_inject_from(rad_listen_t *listen, int argc, char *argv[])
{
	RADCLIENT *client;
	fr_command_socket_t *sock = listen->data;

	if (argc < 1) {
		control_printf_error(listen, "No <ipaddr> was given\n");
		return 0;
	}

	if (!sock->inject_listen) {
		control_printf_error(listen, "You must specify \"inject to\" before using \"inject from\"\n");
		return 0;
	}

	sock->src_ipaddr.af = AF_UNSPEC;
	if (fr_inet_hton(&sock->src_ipaddr, AF_UNSPEC, argv[0], false) < 0) {
		control_printf_error(listen, "Failed parsing IP address; %s\n",
			fr_strerror());
		return 0;
	}

	client = client_listener_find(sock->inject_listen, &sock->src_ipaddr,
				      0);
	if (!client) {
		control_printf_error(listen, "No such client %s\n", argv[0]);
		return 0;
	}
	sock->inject_client = client;

	return CMD_OK;
}

static int command_inject_file(rad_listen_t *listen, int argc, char *argv[])
{
	static int inject_id = 0;
	int ret;
	bool filedone;
	fr_command_socket_t *sock = listen->data;
	rad_listen_t *fake;
	RADIUS_PACKET *packet;
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	FILE *fp;
	RAD_REQUEST_FUNP fun = NULL;
	char buffer[2048];

	if (argc < 2) {
		control_printf_error(listen, "You must specify <input-file> <output-file>\n");
		return 0;
	}

	if (!sock->inject_listen) {
		control_printf_error(listen, "You must specify \"inject to\" before using \"inject file\"\n");
		return 0;
	}

	if (!sock->inject_client) {
		control_printf_error(listen, "You must specify \"inject from\" before using \"inject file\"\n");
		return 0;
	}

	/*
	 *	Output files always go to the logging directory.
	 */
	snprintf(buffer, sizeof(buffer), "%s/%s", radlog_dir, argv[1]);

	fp = fopen(argv[0], "r");
	if (!fp ) {
		control_printf_error(listen, "Failed opening %s: %s\n",
			argv[0], fr_syserror(errno));
		return 0;
	}

	ret = fr_pair_list_afrom_file(NULL, &vp, fp, &filedone);
	fclose(fp);
	if (ret < 0) {
		control_printf_error(listen, "Failed reading attributes from %s: %s\n",
			argv[0], fr_strerror());
		return 0;
	}

	fake = talloc(NULL, rad_listen_t);
	memcpy(fake, sock->inject_listen, sizeof(*fake));

	/*
	 *	Re-write the IO for the listen.
	 */
	fake->encode = null_socket_dencode;
	fake->decode = null_socket_dencode;
	fake->send = null_socket_send;

	packet = fr_radius_alloc(NULL, false);
	packet->src_ipaddr = sock->src_ipaddr;
	packet->src_port = 0;

	packet->dst_ipaddr = sock->dst_ipaddr;
	packet->dst_port = sock->dst_port;
	packet->vps = vp;
	packet->id = inject_id++;

	if (fake->type == RAD_LISTEN_AUTH) {
		packet->code = PW_CODE_ACCESS_REQUEST;
		fun = rad_authenticate;

	} else {
#ifdef WITH_ACCOUNTING
		packet->code = PW_CODE_ACCOUNTING_REQUEST;
		fun = rad_accounting;
#else
		control_printf_error(listen, "This server was built without accounting support.\n");
		fr_radius_free(&packet);
		talloc_free(fake);
		return 0;
#endif
	}

	if (rad_debug_lvl) {
		DEBUG("Injecting %s packet from host %s port 0 code=%d, id=%d",
		      fr_packet_codes[packet->code],
		      inet_ntop(packet->src_ipaddr.af,
				&packet->src_ipaddr.ipaddr,
				buffer, sizeof(buffer)),
		      packet->code, packet->id);

		for (vp = fr_cursor_init(&cursor, &packet->vps);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			fr_pair_snprint(buffer, sizeof(buffer), vp);
			DEBUG("\t%s", buffer);
		}

		WARN("INJECTION IS LEAKING MEMORY!");
	}

	if (!request_receive(NULL, fake, packet, sock->inject_client, fun)) {
		control_printf_error(listen, "Failed to inject request.  See log file for details\n");
		fr_radius_free(&packet);
		talloc_free(fake);
		return 0;
	}

#if 0
	/*
	 *	Remember what the output file is, and remember to
	 *	delete the fake listen when done.
	 */
	request_data_add(request, null_socket_send, 0, talloc_typed_strdup(NULL, buffer), true, false, false);
	request_data_add(request, null_socket_send, 1, fake, true, false, false);

#endif

	return CMD_OK;
}

static int command_set_module_config(rad_listen_t *listen, int argc, char *argv[])
{
	int i, rcode;
	CONF_PAIR *cp;
	CONF_SECTION *cs;
	module_instance_t *instance;
	CONF_PARSER const *variables;
	void *data;

	if (argc < 3) {
		control_printf_error(listen, "No module name or variable was given\n");
		return 0;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return 0;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		control_printf_error(listen, "No such module \"%s\"\n", argv[0]);
		return 0;
	}

	if ((instance->module->type & RLM_TYPE_HUP_SAFE) == 0) {
		control_printf_error(listen, "Cannot change configuration of module as it is cannot be HUP'd.\n");
		return 0;
	}

	variables = cf_section_parse_table(instance->cs);
	if (!variables) {
		control_printf_error(listen, "Cannot find configuration for module\n");
		return 0;
	}

	rcode = -1;
	for (i = 0; variables[i].name != NULL; i++) {
		/*
		 *	FIXME: Recurse into sub-types somehow...
		 */
		if (PW_BASE_TYPE(variables[i].type) == PW_TYPE_SUBSECTION) continue;

		if (strcmp(variables[i].name, argv[1]) == 0) {
			rcode = i;
			break;
		}
	}

	if (rcode < 0) {
		control_printf_error(listen, "No such variable \"%s\"\n", argv[1]);
		return 0;
	}

	i = rcode;		/* just to be safe */

	/*
	 *	It's not part of the dynamic configuration.  The module
	 *	needs to re-parse && validate things.
	 */
	if (variables[i].data) {
		control_printf_error(listen, "Variable cannot be dynamically updated\n");
		return 0;
	}

	data = ((char *) instance->data) + variables[i].offset;

	cp = cf_pair_find(instance->cs, argv[1]);
	if (!cp) return 0;

	/*
	 *	Replace the OLD value in the configuration file with
	 *	the NEW value.
	 *
	 *	FIXME: Parse argv[2] depending on it's data type!
	 *	If it's a string, look for leading single/double quotes,
	 *	end then call tokenize functions???
	 */
	cf_pair_replace(instance->cs, cp, argv[2]);

	rcode = cf_pair_parse(instance->cs, argv[1], variables[i].type, data, argv[2], T_DOUBLE_QUOTED_STRING);
	if (rcode < 0) {
		control_printf_error(listen, "Failed to parse value\n");
		return 0;
	}

	return CMD_OK;
}

static int command_set_module_status(rad_listen_t *listen, int argc, char *argv[])
{
	CONF_SECTION *cs;
	module_instance_t *instance;

	if (argc < 2) {
		control_printf_error(listen, "No module name or status was given\n");
		return 0;
	}

	cs = cf_section_sub_find(main_config.config, "modules");
	if (!cs) return 0;

	instance = module_find(cs, argv[0]);
	if (!instance) {
		control_printf_error(listen, "No such module \"%s\"\n", argv[0]);
		return 0;
	}


	if (strcmp(argv[1], "alive") == 0) {
		instance->force = false;

	} else if (strcmp(argv[1], "dead") == 0) {
		instance->code = RLM_MODULE_FAIL;
		instance->force = true;

	} else {
		int rcode;

		rcode = fr_str2int(mod_rcode_table, argv[1], -1);
		if (rcode < 0) {
			control_printf_error(listen, "Unknown status \"%s\"\n", argv[1]);
			return 0;
		}

		instance->code = rcode;
		instance->force = true;
	}

	return CMD_OK;
}

#ifdef WITH_STATS
static char const *elapsed_names[8] = {
	"1us", "10us", "100us", "1ms", "10ms", "100ms", "1s", "10s"
};

#undef PU
#ifdef WITH_STATS_64BIT
#ifdef PRIu64
#define PU "%" PRIu64
#else
#define PU "%lu"
#endif
#else
#ifdef PRIu32
#define PU "%" PRIu32
#else
#define PU "%u"
#endif
#endif

static int command_print_stats(rad_listen_t *listen, fr_stats_t *stats,
			       int auth, int server)
{
	int i;

	control_printf(listen, "requests\t" PU "\n", stats->total_requests);
	control_printf(listen, "responses\t" PU "\n", stats->total_responses);

	if (auth) {
		control_printf(listen, "accepts\t\t" PU "\n",
			stats->total_access_accepts);
		control_printf(listen, "rejects\t\t" PU "\n",
			stats->total_access_rejects);
		control_printf(listen, "challenges\t" PU "\n",
			stats->total_access_challenges);
	}

	control_printf(listen, "dup\t\t" PU "\n", stats->total_dup_requests);
	control_printf(listen, "invalid\t\t" PU "\n", stats->total_invalid_requests);
	control_printf(listen, "malformed\t" PU "\n", stats->total_malformed_requests);
	control_printf(listen, "bad_authenticator\t" PU "\n", stats->total_bad_authenticators);
	control_printf(listen, "dropped\t\t" PU "\n", stats->total_packets_dropped);
	control_printf(listen, "unknown_types\t" PU "\n", stats->total_unknown_types);

	if (server) {
		control_printf(listen, "timeouts\t" PU "\n", stats->total_timeouts);
	}

	control_printf(listen, "last_packet\t%" PRId64 "\n", (int64_t) stats->last_packet);
	for (i = 0; i < 8; i++) {
		control_printf(listen, "elapsed.%s\t%u\n",
			elapsed_names[i], stats->elapsed[i]);
	}

	return CMD_OK;
}

static int command_stats_state(rad_listen_t *listen, UNUSED int argc, UNUSED char *argv[])
{
	control_printf(listen, "states_created\t\t%" PRIu64 "\n", fr_state_entries_created(global_state));
	control_printf(listen, "states_timeout\t\t%" PRIu64 "\n", fr_state_entries_timeout(global_state));
	control_printf(listen, "states_tracked\t\t%" PRIu32 "\n", fr_state_entries_tracked(global_state));

	return CMD_OK;
}

#ifndef NDEBUG
static int command_stats_memory(rad_listen_t *listen, int argc, char *argv[])
{

	if (!main_config.memory_report) {
		control_printf(listen, "No memory debugging was enabled.\n");
		return CMD_OK;
	}

	if (argc == 0) goto fail;

	if (strcmp(argv[0], "total") == 0) {
		control_printf(listen, "%zd\n", talloc_total_size(NULL));
		return CMD_OK;
	}

	if (strcmp(argv[0], "blocks") == 0) {
		control_printf(listen, "%zd\n", talloc_total_blocks(NULL));
		return CMD_OK;
	}

	if (strcmp(argv[0], "full") == 0) {
		control_printf(listen, "see stdout of the server for the full report.\n");
		fr_log_talloc_report(NULL);
		return CMD_OK;
	}

fail:
	control_printf_error(listen, "Must use 'stats memory [blocks|full|total]'\n");
	return CMD_FAIL;
}
#endif

#ifdef WITH_DETAIL
static FR_NAME_NUMBER state_names[] = {
	{ "unopened", STATE_UNOPENED },
	{ "unlocked", STATE_UNLOCKED },
	{ "processing", STATE_PROCESSING },

	{ "header", STATE_HEADER },
	{ "vps", STATE_VPS },
	{ "queued", STATE_QUEUED },
	{ "running", STATE_RUNNING },
	{ "no-reply", STATE_NO_REPLY },
	{ "replied", STATE_REPLIED },

	{ NULL, 0 }
};

static int command_stats_detail(rad_listen_t *listen, int argc, char *argv[])
{
	rad_listen_t *this;
	listen_detail_t *data, *needle;
	struct stat buf;

	if (argc == 0) {
		control_printf_error(listen, "Must specify <filename>\n");
		return 0;
	}

	data = NULL;
	for (this = main_config.listen; this != NULL; this = this->next) {
		if (this->type != RAD_LISTEN_DETAIL) continue;

		needle = this->data;
		if (!strcmp(argv[0], needle->filename)) {
			data = needle;
			break;
		}
	}

	if (!data) {
		control_printf_error(listen, "No detail file listen\n");
		return 0;
	}

	control_printf(listen, "state\t%s\n",
		fr_int2str(state_names, data->file_state, "?"));

	if ((data->file_state == STATE_UNOPENED) ||
	    (data->file_state == STATE_UNLOCKED)) {
		return CMD_OK;
	}

	/*
	 *	Race conditions: file might not exist.
	 */
	if (stat(data->filename_work, &buf) < 0) {
		control_printf(listen, "packets\t0\n");
		control_printf(listen, "tries\t0\n");
		control_printf(listen, "offset\t0\n");
		control_printf(listen, "size\t0\n");
		return CMD_OK;
	}

	control_printf(listen, "packets\t%d\n", data->packets);
	control_printf(listen, "tries\t%d\n", data->tries);
	control_printf(listen, "offset\t%u\n", (unsigned int) data->offset);
	control_printf(listen, "size\t%u\n", (unsigned int) buf.st_size);

	return CMD_OK;
}
#endif

#ifdef WITH_PROXY
static int command_stats_home_server(rad_listen_t *listen, int argc, char *argv[])
{
	home_server_t *home;

	if (argc == 0) {
		control_printf_error(listen, "Must specify [auth|acct|coa|disconnect] OR <ipaddr> <port>\n");
		return 0;
	}

	if (argc == 1) {
		if (strcmp(argv[0], "auth") == 0) {
			return command_print_stats(listen,
						   &proxy_auth_stats, 1, 1);
		}

#ifdef WITH_ACCOUNTING
		if (strcmp(argv[0], "acct") == 0) {
			return command_print_stats(listen,
						   &proxy_acct_stats, 0, 1);
		}
#endif

#ifdef WITH_ACCOUNTING
		if (strcmp(argv[0], "coa") == 0) {
			return command_print_stats(listen,
						   &proxy_coa_stats, 0, 1);
		}
#endif

#ifdef WITH_ACCOUNTING
		if (strcmp(argv[0], "disconnect") == 0) {
			return command_print_stats(listen,
						   &proxy_dsc_stats, 0, 1);
		}
#endif

		control_printf_error(listen, "Should specify [auth|acct|coa|disconnect]\n");
		return 0;
	}

	home = get_home_server(listen, argc, argv, NULL);
	if (!home) return 0;

	command_print_stats(listen, &home->stats,
			    (home->type == HOME_TYPE_AUTH), 1);
	control_printf(listen, "outstanding\t%d\n", home->currently_outstanding);
	return CMD_OK;
}
#endif

static int command_stats_client(rad_listen_t *listen, int argc, char *argv[])
{
	bool auth = true;
	fr_stats_t *stats;
	RADCLIENT *client, fake;

	if (argc < 1) {
		control_printf_error(listen, "Must specify [auth/acct]\n");
		return 0;
	}

	if (argc == 1) {
		/*
		 *	Global statistics.
		 */
		fake.auth = radius_auth_stats;
#ifdef WITH_ACCOUNTING
		fake.acct = radius_acct_stats;
#endif
#ifdef WITH_COA
		fake.coa = radius_coa_stats;
		fake.dsc = radius_dsc_stats;
#endif
		client = &fake;

	} else {
		/*
		 *	Per-client statistics.
		 */
		client = get_client(listen, argc - 1, argv + 1);
		if (!client) return 0;
	}

	if (strcmp(argv[0], "auth") == 0) {
		auth = true;
		stats = &client->auth;

	} else if (strcmp(argv[0], "acct") == 0) {
#ifdef WITH_ACCOUNTING
		auth = false;
		stats = &client->acct;
#else
		control_printf_error(listen, "This server was built without accounting support.\n");
		return 0;
#endif

	} else if (strcmp(argv[0], "coa") == 0) {
#ifdef WITH_COA
		auth = false;
		stats = &client->coa;
#else
		control_printf_error(listen, "This server was built without CoA support.\n");
		return 0;
#endif

	} else if (strcmp(argv[0], "disconnect") == 0) {
#ifdef WITH_COA
		auth = false;
		stats = &client->dsc;
#else
		control_printf_error(listen, "This server was built without CoA support.\n");
		return 0;
#endif

	} else {
		control_printf_error(listen, "Unknown statistics type\n");
		return 0;
	}

	/*
	 *	Global results for all client.
	 */
	if (argc == 1) {
#ifdef WITH_ACCOUNTING
		if (!auth) {
			return command_print_stats(listen,
						   &radius_acct_stats, auth, 0);
		}
#endif
		return command_print_stats(listen, &radius_auth_stats, auth, 0);
	}

	return command_print_stats(listen, stats, auth, 0);
}


static int command_stats_socket(rad_listen_t *listen, int argc, char *argv[])
{
	bool auth = true;
	rad_listen_t *sock;

	sock = get_socket(listen, argc, argv, NULL);
	if (!sock) return 0;

	if (sock->type != RAD_LISTEN_AUTH) auth = false;

	return command_print_stats(listen, &sock->stats, auth, 0);
}
#endif	/* WITH_STATS */


#ifdef WITH_DYNAMIC_CLIENTS
static int command_add_client_file(rad_listen_t *listen, int argc, char *argv[])
{
	RADCLIENT *c;

	if (argc < 1) {
		control_printf_error(listen, "<file> is required\n");
		return 0;
	}

	/*
	 *	Read the file and generate the client.
	 */
	c = client_read(argv[0], NULL, false);
	if (!c) {
		control_printf_error(listen, "Unknown error reading client file.\n");
		return 0;
	}

	if (!client_add(NULL, c)) {
		control_printf_error(listen, "Unknown error inserting new client.\n");
		client_free(c);
		return 0;
	}

	return CMD_OK;
}


static int command_del_client(rad_listen_t *listen, int argc, char *argv[])
{
	RADCLIENT *client;

	client = get_client(listen, argc, argv);
	if (!client) return 0;

	if (!client->dynamic) {
		control_printf_error(listen, "Client %s was not dynamically defined.\n", argv[0]);
		return 0;
	}

	/*
	 *	DON'T delete it.  Instead, mark it as "dead now".  The
	 *	next time we receive a packet for the client, it will
	 *	be deleted.
	 *
	 *	If we don't receive a packet from it, the client
	 *	structure will stick around for a while.  Oh well...
	 */
	client->lifetime = 1;

	return CMD_OK;
}

static fr_command_table_t command_table_inject[] = {
	{ "to", FR_WRITE,
	  "inject to <ipaddr> <port> - Inject packets to the destination IP and port.",
	  command_inject_to, NULL },

	{ "from", FR_WRITE,
	  "inject from <ipaddr> - Inject packets as if they came from <ipaddr>",
	  command_inject_from, NULL },

	{ "file", FR_WRITE,
	  "inject file <input-file> <output-file> - Inject packet from <input-file>, with results sent to <output-file>",
	  command_inject_file, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_debug_level[] = {
	{ "global", FR_WRITE,
	  "debug level global <number> - Set debug level for global server events and requests written to the main server log.",
	  command_debug_level_global, NULL },

	{ "request", FR_WRITE,
	  "debug level request <number> - Set debug level for requests written to debug file or debug socket.",
	  command_debug_level_request, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_debug[] = {
	{ "condition", FR_WRITE,
	  "debug condition [condition] - Enable debugging for requests matching [condition]",
	  command_debug_condition, NULL },

	{ "file", FR_WRITE,
	  "debug file [filename] - Send all request debug output to [filename]",
	  command_debug_file, NULL },

#if defined(HAVE_FOPENCOOKIE) || defined (HAVE_FUNOPEN)
	{ "socket", FR_WRITE,
	  "debug socket [on|off] - Send all request debug output to radmin socket.",
	  command_debug_socket, NULL },
#endif

	{ "level", FR_READ,
	  "debug level <command> - Set debug levels",
	  NULL, command_table_debug_level },

	{ NULL, 0, NULL, NULL, NULL }
};

#ifdef HAVE_GPERFTOOLS_PROFILER_H
/** Commands to control the gperftools profiler
 *
 */
static fr_command_table_t command_table_profiler_cpu[] = {
	{ "start", FR_WRITE,
	  "profiler cpu start <filename> - Start gperftools cpu profiler, writing output to filename",
	  command_profiler_cpu_start, NULL },

	{ "stop", FR_WRITE,
	  "profiler cpu stop - Stop gperftools cpu profiler, and flush results to disk",
	  command_profiler_cpu_stop, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_profiler[] = {
	{ "cpu", FR_WRITE,
	  "profiler cpu <command> do sub-command of cpu profiler",
	  NULL, command_table_profiler_cpu },

	{ NULL, 0, NULL, NULL, NULL }
};
#endif

static fr_command_table_t command_table_show_debug_level[] = {
	{ "global", FR_WRITE,
	  "show debug level global - Show debug level for global server events and requests written to the main server log.  Higher is more debugging.",
	  command_show_debug_level_global, NULL },

	{ "request", FR_WRITE,
	  "show debug level request - Show debug level for requests written to debug file or debug socket.  Higher is more debugging",
	  command_show_debug_level_request, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};


static fr_command_table_t command_table_show_debug[] = {
	{ "condition", FR_READ,
	  "show debug condition - Shows current debugging condition.",
	  command_show_debug_condition, NULL },

	{ "file", FR_READ,
	  "show debug file - Shows current debugging file.",
	  command_show_debug_file, NULL },

	{ "level", FR_READ,
	  "show debug level <command> - Shows current global or request debug level.",
	  NULL, command_table_show_debug_level },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_show_module[] = {
	{ "config", FR_READ,
	  "show module config <module> - show configuration for given module",
	  command_show_module_config, NULL },
	{ "flags", FR_READ,
	  "show module flags <module> - show other module properties",
	  command_show_module_flags, NULL },
	{ "list", FR_READ,
	  "show module list - shows list of loaded modules",
	  command_show_modules, NULL },
	{ "methods", FR_READ,
	  "show module methods <module> - show sections where <module> may be used",
	  command_show_module_methods, NULL },
	{ "status", FR_READ,
	  "show module status <module> - show the module status",
	  command_show_module_status, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_show_client[] = {
	{ "list", FR_READ,
	  "show client list - shows list of global clients",
	  command_show_clients, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

#ifdef WITH_PROXY
static fr_command_table_t command_table_show_home[] = {
	{ "list", FR_READ,
	  "show home_server list - shows list of home servers",
	  command_show_home_servers, NULL },

	{ "state", FR_READ,
	  "show home_server state <ipaddr> <port> [udp|tcp] - shows state of given home server",
	  command_show_home_server_state, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};
#endif

#ifdef HAVE_GPERFTOOLS_PROFILER_H
static fr_command_table_t command_table_show_profiler_cpu[] = {
	{ "file", FR_WRITE,
	  "show profiler cpu file - show where profile data is being written",
	  command_profiler_cpu_show_file, NULL },

	{ "samples", FR_WRITE,
	  "show profiler cpu samples - show how many profiler samples have been collected",
	  command_profiler_cpu_show_samples, NULL },

	{ "start_time", FR_WRITE,
	  "show profiler cpu start_time - show when profiling last started",
	  command_profiler_cpu_show_start_time, NULL },

	{ "status", FR_WRITE,
	  "show profiler cpu status - show the current profiler state (running or stopped)",
	  command_profiler_cpu_show_status, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_show_profiler[] = {
	{ "cpu", FR_WRITE,
	  "show profiler cpu <command> do sub-command of cpu profiler",
	  NULL, command_table_show_profiler_cpu },

	{ NULL, 0, NULL, NULL, NULL }
};
#endif

static fr_command_table_t command_table_show[] = {
	{ "client", FR_READ,
	  "show client <command> - do sub-command of client",
	  NULL, command_table_show_client },
	{ "config", FR_READ,
	  "show config <path> - shows the value of configuration option <path>",
	  command_show_config, NULL },
	{ "debug", FR_READ,
	  "show debug <command> - show debug properties",
	  NULL, command_table_show_debug },
#ifdef WITH_PROXY
	{ "home_server", FR_READ,
	  "show home_server <command> - do sub-command of home_server",
	  NULL, command_table_show_home },
#endif
	{ "module", FR_READ,
	  "show module <command> - do sub-command of module",
	  NULL, command_table_show_module },

#ifdef HAVE_GPERFTOOLS_PROFILER_H
	{ "profiler", FR_READ,
	  "show profiler <command> - do sub-command of profiler",
	  NULL, command_table_show_profiler },
#endif

	{ "uptime", FR_READ,
	  "show uptime - shows time at which server started",
	  command_uptime, NULL },
	{ "version", FR_READ,
	  "show version - Prints version of the running server",
	  command_show_version, NULL },
	{ NULL, 0, NULL, NULL, NULL }
};

static fr_command_table_t command_table_del_client[] = {
	{ "ipaddr", FR_WRITE,
	  "del client ipaddr <ipaddr> [udp|tcp] [listen <ipaddr> <port>] - Delete a dynamically created client",
	  command_del_client, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};


static fr_command_table_t command_table_del[] = {
	{ "client", FR_WRITE,
	  "del client <command> - Delete client configuration commands",
	  NULL, command_table_del_client },

	{ NULL, 0, NULL, NULL, NULL }
};


static fr_command_table_t command_table_add_client[] = {
	{ "file", FR_WRITE,
	  "add client file <filename> - Add new client definition from <filename>",
	  command_add_client_file, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};


static fr_command_table_t command_table_add[] = {
	{ "client", FR_WRITE,
	  "add client <command> - Add client configuration commands",
	  NULL, command_table_add_client },

	{ NULL, 0, NULL, NULL, NULL }
};
#endif

#ifdef WITH_PROXY
static fr_command_table_t command_table_set_home[] = {
	{ "state", FR_WRITE,
	  "set home_server state <ipaddr> <port> [udp|tcp] [alive|dead] - set state for given home server",
	  command_set_home_server_state, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};
#endif

static fr_command_table_t command_table_set_module[] = {
	{ "config", FR_WRITE,
	  "set module config <module> variable value - set configuration for <module>",
	  command_set_module_config, NULL },

	{ "status", FR_WRITE,
	  "set module status <module> [alive|...] - set the module status to be alive (operating normally), or force a particular code (ok,fail, etc.)",
	  command_set_module_status, NULL },

	{ NULL, 0, NULL, NULL, NULL }
};


static fr_command_table_t command_table_set[] = {
	{ "module", FR_WRITE,
	  "set module <command> - set module commands",
	  NULL, command_table_set_module },
#ifdef WITH_PROXY
	{ "home_server", FR_WRITE,
	  "set home_server <command> - set home server commands",
	  NULL, command_table_set_home },
#endif

	{ NULL, 0, NULL, NULL, NULL }
};


#ifdef WITH_STATS
static fr_command_table_t command_table_stats[] = {
	{ "client", FR_READ,
	  "stats client [auth/acct] <ipaddr> [udp|tcp] [listen <ipaddr> <port>] "
	  "- show statistics for given client, or for all clients (auth or acct)",
	  command_stats_client, NULL },

#ifdef WITH_DETAIL
	{ "detail", FR_READ,
	  "stats detail <filename> - show statistics for the given detail file",
	  command_stats_detail, NULL },
#endif

#ifdef WITH_PROXY
	{ "home_server", FR_READ,
	  "stats home_server [<ipaddr>|auth|acct|coa|disconnect] <port> [udp|tcp] - show statistics for given home server (ipaddr and port), or for all home servers (auth or acct)",
	  command_stats_home_server, NULL },
#endif

	{ "state", FR_READ,
	  "stats state - show statistics for states",
	  command_stats_state, NULL },

	{ "socket", FR_READ,
	  "stats socket <ipaddr> <port> [udp|tcp] "
	  "- show statistics for given socket",
	  command_stats_socket, NULL },

#ifndef NDEBUG
	{ "memory", FR_READ,
	  "stats memory [blocks|full|total] - show statistics on used memory",
	  command_stats_memory, NULL },
#endif

	{ NULL, 0, NULL, NULL, NULL }
};
#endif

fr_command_table_t command_table[] = {
#ifdef WITH_DYNAMIC_CLIENTS
	{ "add", FR_WRITE, NULL, NULL, command_table_add },
#endif
	{ "debug", FR_WRITE,
	  "debug <command> - debugging commands",
	  NULL, command_table_debug },
#ifdef WITH_DYNAMIC_CLIENTS
	{ "del", FR_WRITE, NULL, NULL, command_table_del },
#endif
	{ "hup", FR_WRITE,
	  "hup [module] - sends a HUP signal to the server, or optionally to one module",
	  command_hup, NULL },
	{ "inject", FR_WRITE,
	  "inject <command> - commands to inject packets into a running server",
	  NULL, command_table_inject },

#ifdef HAVE_GPERFTOOLS_PROFILER_H
	{ "profiler", FR_WRITE,
	  "profiler <command> - commands to alter the state of the gperftools profiler",
	  NULL, command_table_profiler },
#endif
	{ "reconnect", FR_READ,
	  "reconnect - reconnect to a running server",
	  NULL, NULL },		/* just here for "help" */
	{ "terminate", FR_WRITE,
	  "terminate - terminates the server, and cause it to exit",
	  command_terminate, NULL },
	{ "set", FR_WRITE, NULL, NULL, command_table_set },
	{ "show",  FR_READ, NULL, NULL, command_table_show },
#ifdef WITH_STATS
	{ "stats",  FR_READ, NULL, NULL, command_table_stats },
#endif

	{ NULL, 0, NULL, NULL, NULL }
};
