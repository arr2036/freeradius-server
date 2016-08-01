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

/*
 * $Id$
 *
 * @file control.c
 * @brief Control socket framework.
 *
 * @copyright 2008,2016 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok <aland@deployingradius.com>
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#ifdef WITH_COMMAND_SOCKET

#include <freeradius-devel/md5.h>
#include <freeradius-devel/channel.h>
#include <freeradius-devel/state.h>
#include <freeradius-devel/command.h>
#include <freeradius-devel/control.h>

#include <libgen.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#ifndef SUN_LEN
#define SUN_LEN(su)  (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <pwd.h>
#include <grp.h>

static FR_NAME_NUMBER mode_names[] = {
	{ "ro",		FR_READ },
	{ "read-only",	FR_READ },
	{ "read-write", FR_READ | FR_WRITE },
	{ "rw",		FR_READ | FR_WRITE },
	{ NULL, 0 }
};

static const CONF_PARSER command_config[] = {
	{ FR_CONF_OFFSET("socket", PW_TYPE_STRING, fr_command_socket_t, path), .dflt = "${run_dir}/radiusd.sock" },
	{ FR_CONF_DEPRECATED("uid", PW_TYPE_STRING, fr_command_socket_t, NULL) },
	{ FR_CONF_OFFSET("gid", PW_TYPE_STRING, fr_command_socket_t, gid_name) },
	{ FR_CONF_OFFSET("mode", PW_TYPE_STRING, fr_command_socket_t, mode_name) },
	{ FR_CONF_OFFSET("peercred", PW_TYPE_BOOLEAN, fr_command_socket_t, peercred), .dflt = "yes" },
	CONF_PARSER_TERMINATOR
};

#if !defined(HAVE_GETPEEREID) && defined(SO_PEERCRED)
/** Get the euid/egid of the peer on the other end of a unix socket
 *
 * This provides the getpeerid function available on some systems.
 *
 * @param[in] fd	to get the peer ID for.
 * @param[out] euid	the euid of the peer.
 * @param[out] egid	the egid of the peer.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
static int getpeereid(int fd, uid_t *euid, gid_t *egid)
{
	struct ucred cr;
	socklen_t cl = sizeof(cr);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) < 0) return -1;

	*euid = cr.uid;
	*egid = cr.gid;
	return 0;
}
#define HAVE_GETPEEREID (1)	/* we now have getpeereid() in this file */
#endif /* HAVE_GETPEEREID */

/** Write a debug message to the STDOUT channel of a socket
 *
 * @param[in] listen	socket to write the message to.
 * @param[in] fmt	string for the message.
 * @param[in] ...	arguments for the message.
 */
ssize_t control_printf(rad_listen_t *listen, char const *fmt, ...)
{
	ssize_t		ret, len;
	va_list		ap;
	char		buffer[256];

	va_start(ap, fmt);
	len = vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	if (listen->status == RAD_LISTEN_STATUS_EOL) return 0;

	ret = fr_channel_write(listen->fd, FR_CHANNEL_STDOUT, buffer, len);
	if (ret <= 0) control_close_socket(listen);

	/*
	 *	FIXME: Keep writing until done?
	 */
	return ret;
}

/** Write an error message to the STDERR channel of a socket
 *
 * @param[in] listen	socket to write the message to.
 * @param[in] fmt	string for the message.
 * @param[in] ...	arguments for the message.
 */
ssize_t control_printf_error(rad_listen_t *listen, char const *fmt, ...)
{
	ssize_t		ret, len;
	va_list		ap;
	char		buffer[256];

	va_start(ap, fmt);
	len = vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	if (listen->status == RAD_LISTEN_STATUS_EOL) return 0;

	ret = fr_channel_write(listen->fd, FR_CHANNEL_STDERR, buffer, len);
	if (ret <= 0) control_close_socket(listen);

	/*
	 *	FIXME: Keep writing until done?
	 */
	return ret;
}

/** Print help text for the current commands list
 *
 */
static void print_help(rad_listen_t *listen, int argc, char *argv[], fr_command_table_t *table, int recursive)
{
	int i;

	/* this should never happen, but if it does then just return gracefully */
	if (!table) return;

	for (i = 0; table[i].command != NULL; i++) {
		if (argc > 0) {
			if (strcmp(table[i].command, argv[0]) == 0) {
				if (table[i].table) {
					print_help(listen, argc - 1, argv + 1, table[i].table, recursive);
				} else {
					if (table[i].help) {
						control_printf(listen, "%s\n", table[i].help);
					}
				}
				return;
			}

			continue;
		}

		if (table[i].help) {
			control_printf(listen, "%s\n",
				table[i].help);
		} else {
			control_printf(listen, "%s <command> - do sub-command of %s\n",
				table[i].command, table[i].command);
		}

		if (recursive && table[i].table) {
			print_help(listen, 0, NULL, table[i].table, recursive);
		}
	}
}

#if !defined(HAVE_OPENAT) || !defined(HAVE_MKDIRAT) || !defined(HAVE_UNLINKAT) || !defined(HAVE_FCHMODAT) || !defined(HAVE_FCHOWNAT)
static int fr_server_domain_socket(UNUSED char const *path, UNUSED gid_t gid)
{
	fr_strerror_printf("Unable to initialise control socket.  Upgrade to POSIX-2008 compliant libc");
	return -1;
}
#else
/** Create a unix socket, and enforce permissions using the file system
 *
 * The way it does this depends on the operating system. On Linux systems permissions can be set on
 * the socket directly and the system will enforce them.
 *
 * On most other systems fchown and fchmod fail when called with socket descriptors, and although
 * permissions can be changed in other ways, they're not enforced.
 *
 * For these systems we use the permissions on the parent directory to enforce permissions on the
 * socket. It's not safe to modify these permissions ourselves due to TOCTOU attacks, so if they don't
 * match what we require, we error out and get the user to change them (which arguably isn't any safer,
 * but releases us of the responsibility).
 *
 * @note must be called without effective root permissions (#fr_suid_down).
 *
 * @param path	where domain socket should be created.
 * @param gid	Alternative group to grant read/write access to the socket.
 * @return
 *	- A file descriptor for the bound socket on success.
 *	- -1 on failure.
 */
static int fr_server_domain_socket(char const *path, gid_t gid)
{
	int			dir_fd = -1, path_fd = -1, sock_fd = -1, parent_fd = -1;
	char const		*name;
	char			*buff = NULL, *dir = NULL, *p;

	uid_t			euid, suid;
	gid_t			egid;

	mode_t			perm = 0;
	mode_t			dir_perm;
	struct stat		st;

	size_t			len;

	socklen_t		socklen;
	struct sockaddr_un	salocal;

	rad_assert(path);

	euid = geteuid();
	egid = getegid();

	/*
	 *	In the Linux implementation, sockets which are visible in the
	 *	filesystem honor the permissions of the directory they are in.
	 *
	 *	Their owner, group, and permissions can be changed.
	 *
	 *	Creation of a new socket will fail if the process does not have
	 *	write and search (execute) permission on the directory the socket
	 *	is created in.
	 *
	 *	Connecting to the socket object requires read/write permission.
	 */
	perm = (S_IREAD | S_IWRITE);
	dir_perm = (S_IREAD | S_IWRITE | S_IEXEC);
	if (gid != (gid_t) -1) {
		perm |= (S_IRGRP | S_IWGRP);
		dir_perm |= (S_IRGRP | S_IXGRP);
	}

	buff = talloc_strdup(NULL, path);
	if (!buff) {
		fr_strerror_printf("Out of memory");
		return -1;
	}

	/*
	 *	Some implementations modify it in place others use internal
	 *	storage *sigh*. dirname also formats the path else we wouldn't
	 *	be using it.
	 */
	dir = dirname(buff);
	if (dir != buff) {
		MEM(dir = talloc_strdup(NULL, dir));
		talloc_free(buff);
	}

	p = strrchr(dir, FR_DIR_SEP);
	if (!p) {
		fr_strerror_printf("Failed determining parent directory");
	error:
		talloc_free(dir);
		if (dir_fd >= 0) close(dir_fd);
		if (path_fd >= 0) close(path_fd);
		if (sock_fd >= 0) close(sock_fd);
		if (parent_fd >= 0) close(parent_fd);
		return -1;
	}

	*p = '\0';

	/*
	 *	Ensure the parent of the control socket directory exists,
	 *	and the euid we're running under has access to it.
	 *
	 *	This must be done suid_down, so we can't be tricked into
	 *	accessing a directory owned by root.
	 */
	parent_fd = open(dir, O_DIRECTORY);
	if (parent_fd < 0) {
		struct passwd *user;
		struct group *group;

		if (errno != ENOENT) {
			fr_strerror_printf("Can't open directory \"%s\": %s", dir, fr_syserror(errno));
			goto error;
		}

		if (rad_getpwuid(NULL, &user, euid) < 0) {
			fr_strerror_printf("Failed resolving euid to user: %s", fr_strerror());
			goto error;
		}
		if (rad_getgrgid(NULL, &group, egid) < 0) {
			fr_strerror_printf("Failed resolving egid to group: %s", fr_strerror());
			talloc_free(user);
			goto error;
		}

		fr_strerror_printf("Can't open directory \"%s\": Create it and allow writing by "
				   "user %s or group %s", dir, user->pw_name, group->gr_name);

		talloc_free(user);
		talloc_free(group);
		goto error;
	}

	*p = FR_DIR_SEP;

	dir_fd = openat(parent_fd, p + 1, O_NOFOLLOW | O_DIRECTORY);
	if (dir_fd < 0) {
		int ret = 0;

		if (errno != ENOENT) {
			rad_file_error(errno);
			fr_strerror_printf("Failed opening control socket directory \"%s\": %s", dir, fr_strerror());
			goto error;
		}

		/*
		 *	This fails if the radius user can't write
		 *	to the parent directory.
		 */
	 	if (mkdirat(parent_fd, p + 1, dir_perm) < 0) {
			rad_file_error(errno);
			fr_strerror_printf("Failed creating control socket directory \"%s\": %s", dir, fr_strerror());
			goto error;
	 	}

		dir_fd = openat(parent_fd, p + 1, O_NOFOLLOW | O_DIRECTORY);
		if (dir_fd < 0) {
			fr_strerror_printf("Failed opening the control socket directory we created: %s",
					   fr_syserror(errno));
			goto error;
		}

		/*
		 *	Can't set groups other than ones we belong
		 *	to unless we suid_up.
		 */
		rad_suid_up();
		if (gid != (gid_t)-1) ret = fchown(dir_fd, euid, gid);
		rad_suid_down();
		if (ret < 0) {
			fr_strerror_printf("Failed changing group of control socket directory: %s",
					   fr_syserror(errno));
			goto error;
		}
	/*
	 *	Control socket dir already exists, but we still need to
	 *	check the permissions are what we expect.
	 */
	} else {
		int ret;
		int client_fd;

		ret = fstat(dir_fd, &st);
		if (ret < 0) {
			fr_strerror_printf("Failed checking permissions of control socket directory: %s",
					   fr_syserror(errno));
			goto error;
		}

		if (st.st_uid != euid) {
			struct passwd *need_user, *have_user;

			if (rad_getpwuid(NULL, &need_user, euid) < 0) {
				fr_strerror_printf("Failed resolving socket dir uid to user: %s", fr_strerror());
				goto error;
			}
			if (rad_getpwuid(NULL, &have_user, st.st_uid) < 0) {
				fr_strerror_printf("Failed resolving socket dir gid to group: %s", fr_strerror());
				talloc_free(need_user);
				goto error;
			}
			fr_strerror_printf("Socket directory \"%s\" must be owned by user %s, currently owned "
					   "by user %s", dir, need_user->pw_name, have_user->pw_name);
			talloc_free(need_user);
			talloc_free(have_user);
			goto error;
		}

		if ((gid != (gid_t)-1) && (st.st_gid != gid)) {
			/*
			 *	Can't set groups other than ones we belong
			 *	to unless we suid_up.
			 */
			rad_suid_up();
			if (gid != (gid_t)-1) ret = fchown(dir_fd, euid, gid);
			rad_suid_down();
			if (ret < 0) {
				struct group *need_group, *have_group;

				if (rad_getgrgid(NULL, &need_group, gid) < 0) {
					fr_strerror_printf("Failed resolving socket directory uid to user: %s",
							   fr_strerror());
					goto error;
				}
				if (rad_getgrgid(NULL, &have_group, st.st_gid) < 0) {
					fr_strerror_printf("Failed resolving socket directory gid to group: %s",
							   fr_strerror());
					talloc_free(need_group);
					goto error;
				}
				fr_strerror_printf("Failed changing ownership of socket directory \"%s\" from "
						   "group %s, to group %s", dir,
						   need_group->gr_name, have_group->gr_name);
				talloc_free(need_group);
				talloc_free(have_group);

				goto error;
			}
		}

		if ((dir_perm & 0777) != (st.st_mode & 0777) &&
		    (fchmod(dir_fd, (st.st_mode & 7000) | dir_perm)) < 0) {
			char str_need[10], oct_need[5];
			char str_have[10], oct_have[5];

			rad_mode_to_str(str_need, dir_perm);
			rad_mode_to_oct(oct_need, dir_perm);
			rad_mode_to_str(str_have, st.st_mode);
			rad_mode_to_oct(oct_have, st.st_mode);
			fr_strerror_printf("Failed changing permissions on socket directory \"%s\" from %s "
					   "(%s) to %s (%s): %s", dir, str_have, oct_have,
					   str_need, oct_need, fr_syserror(errno));

			goto error;
		}

		/*
		 *	Check if a server is already listening on the
		 *	socket?
		 */
		client_fd = fr_socket_client_unix(path, false);
		if (client_fd >= 0) {
			fr_strerror_printf("Control socket '%s' is already in use", path);
			close(client_fd);
			goto error;
		}
		fr_strerror();	/* Clear any errors */
	}

	name = strrchr(path, FR_DIR_SEP);
	if (!name) {
		fr_strerror_printf("Can't determine socket name");
		goto error;
	}
	name++;

	/*
	 *	We've checked the containing directory has the permissions
	 *	we expect, and as we have the FD, and aren't following
	 *	symlinks no one can trick us into changing or creating a
	 *	file elsewhere.
	 *
	 *	It's possible an attacker may still be able to create hard
	 *	links, for the socket file. But they would need write
	 *	access to the directory we just created or verified, so
	 *	this attack vector is unlikely.
	 */
	rad_suid_up();	/* Need to be root to change euid and egid */
	suid = geteuid();

	/*
	 *	Group needs to be changed first, because if we change
	 *	to a non root user, we can no longer set it.
	 */
	if ((gid != (gid_t)-1) && (rad_segid(gid) < 0)) {
		fr_strerror_printf("Failed setting egid: %s", fr_strerror());
		rad_suid_down();
		goto error;
	}

	/*
	 *	Reset euid back to FreeRADIUS user
	 */
	if (rad_seuid(euid) < 0) {
		fr_strerror_printf("Failed restoring euid: %s", fr_strerror());
		rad_segid(egid);
		rad_suid_down();
		goto error;
	}

	/*
	 *	The original code, did openat, used fstat to figure out
	 *	what type the file was and then used unlinkat to unlink
	 *	it. Except on OSX (at least) openat refuses to open
	 *	socket files. So we now rely on the fact that unlinkat
	 *	has sane and consistent behaviour, and will not unlink
	 *	directories. unlinkat should also fail if the socket user
	 *	hasn't got permission to modify the socket.
	 */
	if ((unlinkat(dir_fd, name, 0) < 0) && (errno != ENOENT)) {
		fr_strerror_printf("Failed removing stale socket: %s", fr_syserror(errno));
	sock_error:
		/*
		 *	Restore suid to ensure rad_suid_up continues
		 *	to work correctly.
		 */
		rad_seuid(suid);
		if (gid != (gid_t)-1) rad_segid(egid);
		/*
		 *	Then SUID down, to ensure rad_suid_up/down continues
		 *	to work correctly.
		 */
		rad_suid_down();
		goto error;
	}

	/*
	 *	At this point we should have established a secure directory
	 *	to house our socket, and cleared out any stale sockets.
	 */
	sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		fr_strerror_printf("Failed opening socket: %s", fr_syserror(errno));
		goto sock_error;
	}

#ifdef HAVE_BINDAT
	len = strlen(name);
#else
	len = strlen(path);
#endif
	if (len >= sizeof(salocal.sun_path)) {
		fr_strerror_printf("Path too long in socket filename");
		goto sock_error;
	}

	memset(&salocal, 0, sizeof(salocal));
	salocal.sun_family = AF_UNIX;

#ifdef HAVE_BINDAT
	memcpy(salocal.sun_path, name, len + 1); /* SUN_LEN does strlen */
#else
	memcpy(salocal.sun_path, path, len + 1); /* SUN_LEN does strlen */
#endif
	socklen = SUN_LEN(&salocal);

	/*
	 *	The correct function to use here is bindat(), but only
	 *	quite recent versions of FreeBSD actually have it, and
	 *	it's definitely not POSIX.
	 */
#ifdef HAVE_BINDAT
	if (bindat(dir_fd, sock_fd, (struct sockaddr *)&salocal, socklen) < 0) {
#else
	if (bind(sock_fd, (struct sockaddr *)&salocal, socklen) < 0) {
#endif
		fr_strerror_printf("Failed binding socket: %s", fr_syserror(errno));
		goto sock_error;
	}

	/*
	 *	Previous code used fchown to set ownership before the
	 *	socket was bound.  Unfortunately this only seemed to
	 *	work on Linux, on OSX and FreeBSD this operation would
	 *	throw an EINVAL error.
	 */
        if (fchownat(dir_fd, name, euid, gid, AT_SYMLINK_NOFOLLOW) < 0) {
                struct passwd *user;
                struct group *group;
                int fchown_err = errno;


                if (rad_getpwuid(NULL, &user, euid) < 0) {
                        fr_strerror_printf("Failed resolving socket uid to user: %s", fr_strerror());
                        goto sock_error;
                }
                if (rad_getgrgid(NULL, &group, gid) < 0) {
                        fr_strerror_printf("Failed resolving socket gid to group: %s", fr_strerror());
                        talloc_free(user);
                        goto sock_error;
                }

                fr_strerror_printf("Failed changing socket ownership to %s:%s: %s", user->pw_name, group->gr_name,
                                   fr_syserror(fchown_err));
                talloc_free(user);
                talloc_free(group);
                goto sock_error;
        }

	/*
	 *	Direct socket permissions are only useful on Linux which
	 *	actually enforces them. BSDs may not... or they may...
	 *	OSX 10.11.x (EL-Capitan) seems to.
	 *
	 *	Previous code used fchmod on sock_fd before the bind,
	 *	but this didn't always set the correct permissions.
	 *
	 *	fchmodat seems to work more reliably, and has the same
	 *	resistance against TOCTOU attacks.
	 *
	 *	AT_SYMLINK_NOFOLLOW causes this to fail on Linux.
	 */
	if (fchmodat(dir_fd, name, perm, 0) < 0) {
		char str_need[10], oct_need[5];

		rad_mode_to_str(str_need, perm);
		rad_mode_to_oct(oct_need, perm);
		fr_strerror_printf("Failed changing socket permissions to %s (%s): %s", str_need, oct_need,
				   fr_syserror(errno));
		goto sock_error;
	}

	if (listen(sock_fd, 8) < 0) {
		fr_strerror_printf("Failed listening on socket: %s", fr_syserror(errno));
		goto sock_error;
	}

	if (fr_nonblock(sock_fd) < 0) {
		fr_strerror_printf("Failed setting nonblock on socket: %s", fr_strerror());
		goto sock_error;
	}

	/*
	 *	Restore suid to ensure rad_suid_up continues
	 *	to work correctly.
	 */
	rad_seuid(suid);
	if (gid != (gid_t)-1) rad_segid(egid);
	rad_suid_down();

	close(dir_fd);
	if (path_fd >= 0) close(path_fd);
	close(parent_fd);

	return sock_fd;
}
#endif

/** Shutdown a command socket
 *
 * Also removes the socket FD from the event loop.
 *
 * @param[in] this	The listener to close.
 */
void control_close_socket(rad_listen_t *this)
{
	this->status = RAD_LISTEN_STATUS_EOL;

	/*
	 *	This removes the socket from the event fd, so no one
	 *	will be calling us any more.
	 */
	radius_update_listener(this);
}

/*
 *	For encode/decode stuff
 */
int null_socket_dencode(UNUSED rad_listen_t *listen, UNUSED REQUEST *request)
{
	return 0;
}

int null_socket_send(UNUSED rad_listen_t *listen, REQUEST *request)
{
	vp_cursor_t cursor;
	char *output_file;
	FILE *fp;

	output_file = request_data_reference(request, (void *)null_socket_send, 0);
	if (!output_file) {
		ERROR("No output file for injected packet %" PRIu64 "", request->number);
		return 0;
	}

	fp = fopen(output_file, "w");
	if (!fp) {
		ERROR("Failed to send injected file to %s: %s", output_file, fr_syserror(errno));
		return 0;
	}

	if (request->reply->code != 0) {
		char const *what = "reply";
		VALUE_PAIR *vp;
		char buffer[1024];

		if (request->reply->code < FR_MAX_PACKET_CODE) {
			what = fr_packet_codes[request->reply->code];
		}

		fprintf(fp, "%s\n", what);

		if (rad_debug_lvl) {
			RDEBUG("Injected %s packet to host %s port 0 code=%d, id=%d", what,
			       inet_ntop(request->reply->src_ipaddr.af,
					 &request->reply->src_ipaddr.ipaddr,
					 buffer, sizeof(buffer)),
					 request->reply->code, request->reply->id);
		}

		RINDENT();
		for (vp = fr_cursor_init(&cursor, &request->reply->vps);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			fr_pair_snprint(buffer, sizeof(buffer), vp);
			fprintf(fp, "%s\n", buffer);
			RDEBUG("%s", buffer);
		}
		REXDENT();
	}
	fclose(fp);

	return 0;
}

/** Common destructor for TCP and Unix sockets
 *
 * @param[in] cmd_socket to destroy.
 */
static int _control_socket_free(fr_command_socket_t *cmd_socket)
{
	/*
	 *	If it's a TCP socket, don't do anything.
	 */
	if (cmd_socket->magic != COMMAND_SOCKET_MAGIC) return 0;

	if (!cmd_socket->copy) return 0;
	unlink(cmd_socket->copy);

	return 0;
}

/** Processes configuration for unix sockets
 *
 * @param[in] cs	containing the configuration.
 * @param[in] this	listener we're parsing the config for.
 * @return
 *	- 0 on success.
 	- -1 on failure.
 */
static int control_socket_parse_unix(CONF_SECTION *cs, rad_listen_t *this)
{
	fr_command_socket_t *sock;

	sock = this->data;
	talloc_set_type(sock, fr_command_socket_t);
	talloc_set_destructor(sock, _control_socket_free);

	if (cf_section_parse(cs, sock, command_config) < 0) return -1;

	/*
	 *	Can't get uid or gid of connecting user, so can't do
	 *	peercred authentication.
	 */
#ifndef HAVE_GETPEEREID
	if (sock->peercred && (sock->uid_name || sock->gid_name)) {
		ERROR("System does not support uid or gid authentication for sockets");
		return -1;
	}
#endif

	sock->magic = COMMAND_SOCKET_MAGIC;
	sock->copy = NULL;
	if (sock->path) sock->copy = talloc_typed_strdup(sock, sock->path);

	if (sock->gid_name) {
		if (rad_getgid(cs, &sock->gid, sock->gid_name) < 0) {
			ERROR("Failed resolving gid of group %s: %s", sock->gid_name, fr_strerror());
			return -1;
		}
	} else {
		sock->gid = -1;
	}

	if (!sock->mode_name) {
		sock->mode = FR_READ;
	} else {
		sock->mode = fr_str2int(mode_names, sock->mode_name, 0);
		if (!sock->mode) {
			ERROR("Invalid mode name \"%s\"", sock->mode_name);
			return -1;
		}
	}

	return 0;
}

static int control_socket_open_unix(UNUSED CONF_SECTION *cs, rad_listen_t *this)
{
	fr_command_socket_t *sock;

	sock = this->data;

	this->fd = fr_server_domain_socket(sock->path, sock->gid);
	if (this->fd < 0) {
		ERROR("%s", fr_strerror());
		if (sock->copy) TALLOC_FREE(sock->copy);
		return -1;
	}

	return 0;
}

static int control_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int			rcode;
	CONF_PAIR const		*cp;
	listen_socket_t		*sock;

	cp = cf_pair_find(cs, "socket");
	if (cp) return control_socket_parse_unix(cs, this);

	rcode = common_socket_parse(cs, this);
	if (rcode < 0) return -1;

#ifdef WITH_TLS
	if (this->tls) {
		cf_log_err_cs(cs,
			   "TLS is not supported for control sockets");
		return -1;
	}
#endif

	sock = this->data;
	if (sock->proto != IPPROTO_TCP) {
		cf_log_err_cs(cs,
			   "UDP is not supported for control sockets");
		return -1;
	}

	return 0;
}

static int control_socket_open(CONF_SECTION *cs, rad_listen_t *this)
{
	CONF_PAIR const *cp;

	cp = cf_pair_find(cs, "socket");
	if (cp) return control_socket_open_unix(cs, this);

	return common_socket_open(cs, this);
}

static int control_socket_print(rad_listen_t const *this, char *buffer, size_t bufsize)
{
	fr_command_socket_t *sock = this->data;

	if (sock->magic != COMMAND_SOCKET_MAGIC) {
		return common_socket_print(this, buffer, bufsize);
	}

	snprintf(buffer, bufsize, "command file %s", sock->path);
	return 1;
}

/** Splits command string in place into individual commands
 *
 * String split routine.  Splits an input string IN PLACE
 * into pieces, based on spaces.
 *
 * @param[in] str	to split.
 * @param[out] argv	array of pointers to write strings to.
 * @param[in] max_argc	the length of the argv array.
 */
static int dict_str_to_argv_x(char *str, char **argv, int max_argc)
{
	int argc = 0;

	while (*str) {
		if (argc >= max_argc) return argc;

		/*
		 *	Chop out comments early.
		 */
		if (*str == '#') {
			*str = '\0';
			break;
		}

		while ((*str == ' ') ||
		       (*str == '\t') ||
		       (*str == '\r') ||
		       (*str == '\n')) *(str++) = '\0';

		if (!*str) return argc;

		argv[argc++] = str;

		if ((*str == '\'') || (*str == '"')) {
			char quote = *str;
			char *p = str + 1;

			while (true) {
				if (!*p) return -1;

				if (*p == quote) {
					str = p + 1;
					break;
				}

				/*
				 *	Handle \" and nothing else.
				 */
				if (*p == '\\') {
					p += 2;
					continue;
				}

				p++;
			}
		}

		while (*str &&
		       (*str != ' ') &&
		       (*str != '\t') &&
		       (*str != '\r') &&
		       (*str != '\n')) str++;
	}

	return argc;
}

#define MAX_ARGV (16)

/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
 */
static int control_domain_recv_data(rad_listen_t *listen)
{
	int			i;
	uint32_t		status;
	ssize_t			r;
	size_t			len;
	int			argc;

	fr_command_socket_t	*cmd_sock = talloc_get_type_abort(listen->data, fr_command_socket_t);
	fr_channel_type_t	channel;

	char			*my_argv[MAX_ARGV], **argv;
	fr_command_table_t	*table;
	uint8_t	const		*data;
	char 			*command = NULL;
	char			*p, *end;

	switch (fr_channel_read(&data, &len, &channel, listen->fd, cmd_sock->buff)) {
	case FR_CHANNEL_STATUS_FAIL:
	do_close:
		control_close_socket(listen);
		talloc_free(command);
		return 0;

	case FR_CHANNEL_STATUS_AGAIN:
		return 0;

	case FR_CHANNEL_STATUS_SUCCESS:
		if (len == 0) goto do_next;
	}

	status = 0;

	command = talloc_bstrndup(cmd_sock->buff, (char const *)data, len);
	DEBUG("radmin> %s", command);

	argc = dict_str_to_argv_x(command, my_argv, MAX_ARGV);
	if (argc == 0) goto do_next; /* empty strings are OK */
	if (argc < 0) {
		control_printf_error(listen, "Failed parsing command '%s'.\n", command);
		goto do_next;
	}

	argv = my_argv;

	for (p = command, end = p + len; p < end; p++) {
		if (*p < 0x20) {
			*p = '\0';
			break;
		}
	}

	/*
	 *	Hard-code exit && quit.
	 */
	if ((strcmp(argv[0], "exit") == 0) ||
	    (strcmp(argv[0], "quit") == 0)) goto do_close;

	table = command_table;
 retry:
	len = 0;
	for (i = 0; table[i].command != NULL; i++) {
		if (strcmp(table[i].command, argv[0]) == 0) {
			/*
			 *	Check permissions.
			 */
			if (((cmd_sock->mode & FR_WRITE) == 0) &&
			    ((table[i].mode & FR_WRITE) != 0)) {
				control_printf_error(listen, "You do not have write permission.  "
						     "See \"mode = rw\" in the \"listen\" section for this socket.\n");
				goto do_next;
			}

			if (table[i].table) {
				/*
				 *	This is the last argument, but
				 *	there's a sub-table.  Print help.
				 *
				 */
				if (argc == 1) {
					table = table[i].table;
					goto do_help;
				}

				argc--;
				argv++;
				table = table[i].table;
				goto retry;
			}

			if ((argc == 2) && (strcmp(argv[1], "?") == 0)) goto do_help;

			if (!table[i].func) {
				control_printf_error(listen, "Invalid command\n");
				goto do_next;
			}

			status = table[i].func(listen, argc - 1, argv + 1);
			goto do_next;
		}
	}

	/*
	 *	No such command
	 */
	if (!len) {
		if ((strcmp(argv[0], "help") == 0) ||
		    (strcmp(argv[0], "?") == 0)) {
			int recursive;

		do_help:
			if ((argc > 1) && (strcmp(argv[1], "-r") == 0)) {
				recursive = true;
				argc--;
				argv++;
			} else {
				recursive = false;
			}

			print_help(listen, argc - 1, argv + 1, table, recursive);
			goto do_next;
		}

		control_printf_error(listen, "Unknown command \"%s\"\n", argv[0]);
	}

 do_next:
	talloc_free(command);

	r = fr_channel_write(listen->fd, FR_CHANNEL_CMD_STATUS, &status, sizeof(status));
	if (r <= 0) goto do_close;

	return 0;
}

static int control_tcp_recv(rad_listen_t *listen)
{
	listen_socket_t		*listen_sock = talloc_get_type_abort(listen->data, listen_socket_t);
	fr_command_socket_t	*cmd_sock = talloc_get_type_abort(listen_sock->data, fr_command_socket_t);
	fr_channel_type_t	channel;

	if (!cmd_sock->auth) {
		uint8_t const	*data;
		size_t		len;
		uint8_t		expected[16];

		switch (fr_channel_read(&data, &len, &channel, listen->fd, cmd_sock->buff)) {
		case FR_CHANNEL_STATUS_AGAIN:
			return 0;

		case FR_CHANNEL_STATUS_FAIL:
		do_close:
			control_close_socket(listen);
			return 0;

		case FR_CHANNEL_STATUS_SUCCESS:
			break;
		}

		if ((len != sizeof(expected)) || (channel != FR_CHANNEL_AUTH_RESPONSE)) {
			ERROR("Invalid authentication response, expected %zu bytes on channel %s, "
			      "got %zu bytes on channel %s",
			      sizeof(expected),
			      fr_int2str(fr_channel_type_table, FR_CHANNEL_AUTH_RESPONSE, "<INVALID>"),
			      len,
			      fr_int2str(fr_channel_type_table, FR_CHANNEL_AUTH_RESPONSE, "<INVALID>"));
			goto do_close;
		}

		fr_hmac_md5(expected, (void const *) listen_sock->client->secret,
			    strlen(listen_sock->client->secret),
			    data, sizeof(expected));

		if (fr_radius_digest_cmp(expected, data + sizeof(expected), sizeof(expected)) != 0) {
			ERROR("radmin failed challenge: Closing socket");
			goto do_close;
		}

		cmd_sock->auth = true;

	}

	return control_domain_recv_data(listen);
}

/*
 *	Should never be called.  The functions should just call write().
 */
static int control_tcp_send(UNUSED rad_listen_t *listen, UNUSED REQUEST *request)
{
	return 0;
}

static int control_domain_recv(rad_listen_t *listen)
{
	return control_domain_recv_data(listen);
}

/*
 *	Write 32-bit magic number && version information.
 */
static int control_magic_recv(rad_listen_t *listen, fr_channel_buff_t *buff, bool do_challenge)
{
	ssize_t			ret;
	size_t			len;
	uint32_t		magic;
	fr_channel_type_t	channel;
	uint8_t			challenge[16];
	uint8_t	const		*data;

	/*
	 *	Start off by reading 4 bytes of magic, followed by 4 bytes of zero.
	 */
	switch (fr_channel_read(&data, &len, &channel, listen->fd, buff)) {
	case FR_CHANNEL_STATUS_AGAIN:
		return 0;

	case FR_CHANNEL_STATUS_FAIL:
		ERROR("Failed reading magic: %s", fr_strerror());

	do_close:
		control_close_socket(listen);
		return 0;

	case FR_CHANNEL_STATUS_SUCCESS:
		break;
	}

	if ((len != 8) || (channel != FR_CHANNEL_INIT_ACK)) {
		ERROR("Invalid magic data, expected 8 bytes on channel %s, got %zu bytes on channel %s",
		      fr_int2str(fr_channel_type_table, FR_CHANNEL_INIT_ACK, "<INVALID>"),
		      len,
		      fr_int2str(fr_channel_type_table, channel, "<INVALID>"));
		goto do_close;
	}

	magic = htonl(0xf7eead16);
	if (memcmp(&magic, data, sizeof(magic)) != 0) {
		ERROR("Incompatible versions");
		goto do_close;
	}

	DEBUG3("Got version check challenge, sending version check response");
	/*
	 *	Ack the magic + 4 bytes of zero back.
	 */
	ret = fr_channel_write(listen->fd, FR_CHANNEL_INIT_ACK, data, 8);
	if (ret <= 0) {
		ERROR("Failed writing magic: %s", fr_syserror(errno));
		goto do_close;
	}

	if (do_challenge) {
		size_t	i;

		for (i = 0; i < sizeof(challenge); i++) challenge[i] = fr_rand();

		ret = fr_channel_write(listen->fd, FR_CHANNEL_AUTH_CHALLENGE, challenge, sizeof(challenge));
		if (ret <= 0) {
			ERROR("Failed writing auth challenge: %s", fr_syserror(errno));
			goto do_close;
		}

	}

	return 1;
}

/** Initial state, perform the magic handshake
 *
 */
static int control_init_recv(rad_listen_t *listen)
{
	int			rcode;
	fr_command_socket_t	*cmd_sock = talloc_get_type_abort(listen->data, fr_command_socket_t);

	if (cmd_sock->magic == COMMAND_SOCKET_MAGIC) {
		rcode = control_magic_recv(listen, cmd_sock->buff, false);
		if (rcode <= 0) return rcode;

		listen->recv = control_domain_recv;
	} else {
		listen_socket_t *sock2 = listen->data;

		rcode = control_magic_recv(listen, (fr_channel_buff_t *) sock2->packet, true);
		if (rcode <= 0) return rcode;

		listen->recv = control_tcp_recv;
	}

	return 0;
}

/** Process a new incoming client socket
 *
 * @param[in] listen	socket the new connection was made on.
 * @return
 *	- 0 on success.
 *	- -1 on success.
 */
static int control_domain_accept(rad_listen_t *listen)
{
	int				newfd;
	rad_listen_t			*this;
	socklen_t			salen;
	struct sockaddr_storage		src;
	fr_command_socket_t		*cmd_sock = talloc_get_type_abort(listen->data, fr_command_socket_t);

	salen = sizeof(src);

	DEBUG2("New connection request on control socket");

	newfd = accept(listen->fd, (struct sockaddr *)&src, &salen);
	if (newfd < 0) {
		/*
		 *	Non-blocking sockets must handle this.
		 */
		if (errno == EWOULDBLOCK) return 0;

		ERROR("Failed accepting connection: %s", fr_syserror(errno));
		return -1;
	}

	/*
	 *	Is likely redundant as newfd should inherit blocking
	 *	from listen->fd.  But better to be safe.
	 */
	fr_nonblock(newfd);

	/*
	 *	Disable sigpipe.  We can't mask it globally on BSDs
	 */
	if (fr_sigpipe_disable(newfd) < 0) {
		ERROR("%s", fr_strerror());
		return -1;
	}

#ifdef HAVE_GETPEEREID
	/*
	 *	Perform user authentication.
	 */
	if (cmd_sock->peercred) {
		uid_t uid;
		gid_t gid;

		if (getpeereid(newfd, &uid, &gid) < 0) {
			ERROR("Failed getting peer credentials for %s: %s", cmd_sock->path, fr_syserror(errno));
			close(newfd);
			return -1;
		}

		/*
		 *	Only do UID checking if the caller is
		 *	non-root.  The superuser can do anything, so
		 *	we might as well let them.
		 */
		if ((uid != 0) && (uid != geteuid()) && (cmd_sock->gid_name && (cmd_sock->gid != gid))) {
			ERROR("Unauthorized connection to %s from uid %ld, gid %ld",
			      cmd_sock->path, (long int) uid, (long int) gid);
			close(newfd);
			return -1;
		}
	}
#endif

	/*
	 *	Add the new listen.
	 */
	this = listen_alloc(listen, listen->type, listen->proto);
	if (!this) return 0;

	/*
	 *	Copy everything, including the pointer to the socket
	 *	information.
	 */
	cmd_sock = this->data;
	talloc_set_type(cmd_sock, fr_command_socket_t);

	memcpy(this, listen, sizeof(*this));
	this->status = RAD_LISTEN_STATUS_INIT;
	this->next = NULL;
	this->data = cmd_sock;	/* fix it back */
	this->fd = newfd;
	this->recv = control_init_recv;

	cmd_sock->magic = COMMAND_SOCKET_MAGIC;
	cmd_sock->user[0] = '\0';
	cmd_sock->path = ((fr_command_socket_t *) listen->data)->path;
	cmd_sock->mode = ((fr_command_socket_t *) listen->data)->mode;
	MEM(cmd_sock->buff = fr_channel_buff_alloc(cmd_sock, 2048));


	/*
	 *	Tell the event loop that we have a new FD
	 */
	DEBUG3("Adding new listener for fd %i", newfd);
	radius_update_listener(this);

	/*
	 *	Start off by sending the magic handshake,
	 *	called when radmin sends it us half of the handshake.
	 */
	DEBUG3("Waiting for version check challenge...");

	return 0;
}


/*
 *	Send an authentication response packet
 */
static int control_domain_send(UNUSED rad_listen_t *listen, UNUSED REQUEST *request)
{
	return 0;
}


static int control_socket_encode(UNUSED rad_listen_t *listen, UNUSED REQUEST *request)
{
	return 0;
}


static int control_socket_decode(UNUSED rad_listen_t *listen, UNUSED REQUEST *request)
{
	return 0;
}

#endif /* WITH_COMMAND_SOCKET */
