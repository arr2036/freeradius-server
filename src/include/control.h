/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef _FR_CONTROL_H
#define _FR_CONTROL_H
/**
 * $Id$
 *
 * @file include/control.h
 * @brief API to add client definitions to the server, both on startup and at runtime.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(control_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#define FR_READ  (1)
#define FR_WRITE (2)

#define COMMAND_SOCKET_MAGIC (0xffdeadee)
typedef struct fr_command_socket_t {
	uint32_t		magic;
	char const		*path;
	char			*copy;		/* <sigh> */
	gid_t			gid;		//!< Additional group authorized to connect to socket.
	char const		*gid_name;	//!< Name of additional group (resolved to gid later).
	char const		*mode_name;
	bool			peercred;
	char			user[256];

	/*
	 *	The next few entries handle fake packets injected by
	 *	the control socket.
	 */
	fr_ipaddr_t		src_ipaddr; /* src_port is always 0 */
	fr_ipaddr_t		dst_ipaddr;
	uint16_t		dst_port;
	rad_listen_t		*inject_listen;
	RADCLIENT		*inject_client;

	bool			auth;
	int			mode;
	fr_channel_buff_t  	*buff;
} fr_command_socket_t;

extern fr_cond_t *debug_condition;
extern fr_log_t debug_log;

ssize_t		control_printf(rad_listen_t *listen, char const *fmt, ...) CC_HINT(format (printf, 2, 3));

ssize_t 	control_printf_error(rad_listen_t *listen, char const *fmt, ...) CC_HINT(format (printf, 2, 3));

void		control_close_socket(rad_listen_t *this);

int		null_socket_send(UNUSED rad_listen_t *listen, REQUEST *request);

int		null_socket_dencode(UNUSED rad_listen_t *listen, UNUSED REQUEST *request);

#ifdef __cplusplus
}
#endif
#endif
