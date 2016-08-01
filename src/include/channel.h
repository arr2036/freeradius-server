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
#ifndef _FR_CHANNEL_H
#define _FR_CHANNEL_H
/**
 * $Id$
 *
 * @file include/channel.h
 * @brief API to provide distinct communication channels for the radmin protocol.
 *
 * @copyright 2015 Alan DeKok <aland@deployingradius.com>
 */
RCSIDH(channel_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef enum fr_channel_type_t {
	FR_CHANNEL_STDIN = 0,
	FR_CHANNEL_STDOUT,
	FR_CHANNEL_STDERR,
	FR_CHANNEL_CMD_STATUS,
	FR_CHANNEL_INIT_ACK,
	FR_CHANNEL_AUTH_CHALLENGE,
	FR_CHANNEL_AUTH_RESPONSE,
	FR_CHANNEL_NOTIFY,
	FR_CHANNEL_UNKNOWN
} fr_channel_type_t;

typedef enum fr_channel_status_t {
	FR_CHANNEL_STATUS_FAIL = -1,		//!< Failed reading/writing to channel.
	FR_CHANNEL_STATUS_SUCCESS = 0,		//!< read/wrote a complete buffer.
	FR_CHANNEL_STATUS_AGAIN,		//!< Need to be called again to complete operation.
} fr_channel_status_t;

typedef enum fr_channel_notify_t {
	FR_NOTIFY_NONE = 0,
	FR_NOTIFY_BUFFERED,
	FR_NOTIFY_UNBUFFERED
} fr_channel_notify_t;

typedef struct fr_channel_buff fr_channel_buff_t;

extern FR_NAME_NUMBER fr_channel_type_table[];

fr_channel_status_t	fr_channel_read(uint8_t const **out, size_t *outlen, fr_channel_type_t *channel,
					int fd, fr_channel_buff_t *buff);

ssize_t			fr_channel_write(int fd, fr_channel_type_t channel, void const *in, size_t inlen);

fr_channel_buff_t	*fr_channel_buff_alloc(TALLOC_CTX *ctx, size_t preallocate);
#ifdef __cplusplus
}
#endif
#endif /* _FR_CHANNEL_H */
