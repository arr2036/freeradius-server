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
#ifndef _FR_COMMAND_H
#define _FR_COMMAND_H
/**
 * $Id$
 *
 * @file include/command.h
 * @brief API to add client definitions to the server, both on startup and at runtime.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(command_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*fr_command_func_t)(rad_listen_t *, int, char *argv[]);

typedef struct fr_command_table_t fr_command_table_t;
struct fr_command_table_t {
	char const		*command;
	int			mode;		/* read/write */
	char const		*help;
	fr_command_func_t	func;
	fr_command_table_t	*table;
};

extern fr_command_table_t command_table[];

#ifdef __cplusplus
}
#endif
#endif
