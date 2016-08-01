/*
 * radmin.c	RADIUS Administration tool.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2015   The FreeRADIUS server project
 * Copyright 2015   Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/channel.h>

#define FR_CHANNEL_BUFF_PRE_MAX		(1024)		//!< The maximum amount of data we drain in any read call.
#define FR_CHANNEL_BUFF_PRE_MIN		(128)		//!< The minimum amount of data we (could) drain in
							//!< any read call.

/** The on the wire format of a channel header
 *
 */
typedef struct channel_header {
	uint16_t		channel;		//!< Channel number.
	uint16_t		length;			//!< Length of channel data.
} CC_HINT(__packed__) channel_header_t;

#define FR_CHANNEL_MAX_PACKET_LEN 	UINT16_MAX + sizeof(channel_header_t)	//!< The maximum packet size.

/** Expandable buffer
 *
 * Allows reads to be performed in stages until we have a complete result.
 */
struct fr_channel_buff {
	fr_channel_type_t	channel;		//!< Channel we're currently receiving data for.
	size_t			expected;		//!< How much data the channel buffer said to expect.
	size_t			used;			//!< How much of the buffer was used.
	uint8_t			*data;			//!< Data read from the socket.
	unsigned int		segments;		//!< How many read operations we've performed so far.
};

FR_NAME_NUMBER fr_channel_type_table[] = {
	{ "stdin", 		FR_CHANNEL_STDIN },
	{ "stdout",		FR_CHANNEL_STDOUT },
	{ "stderr",		FR_CHANNEL_STDERR },
	{ "cmd_status",		FR_CHANNEL_CMD_STATUS },
	{ "init_ack",		FR_CHANNEL_INIT_ACK },
	{ "auth_challenge",	FR_CHANNEL_AUTH_CHALLENGE },
	{ "auth_response",	FR_CHANNEL_AUTH_RESPONSE },
	{ "notify",		FR_CHANNEL_NOTIFY },
	{ "unknown",		FR_CHANNEL_UNKNOWN }
};

/** Read raw data from a socket absorbing EINTR
 *
 * @note Will not trim buff->data to the used length.
 *
 * @param[in] fd	to read from.
 * @param[in] buff	to read data into.
 * @param[in] max	size to expand the buffer to.
 * @return
 *	- >0	the amount of data read in this call to channel_read.
 *	- 0	no data was available (this may be OK for some channels).
 *	- <0	an error occurred (see errno).
 */
static ssize_t channel_read(int fd, fr_channel_buff_t *buff, size_t max)
{
	size_t		buff_len, want, had = buff->used;
	ssize_t		slen;
	uint8_t		*tmp;
	size_t		i;

	if (!buff) {
		errno = EINVAL;
		return -1;
	}

	buff_len = talloc_array_length(buff->data);

	/*
	 *	Figure out how much we expect to read...
	 */
	if (buff->expected) {
		if (buff->expected > max) {
			errno = ENOBUFS;
			return -1;
		}
		want = buff->expected;
	} else {
		want = max && (1024 > max) ? max : 1024;
	}

	/*
	 *	...and pre-expand the buffer if we need to.
	 */
	if (want > buff_len) {
		tmp = talloc_realloc(buff, buff->data, uint8_t, want);
		if (!tmp) {
			errno = ENOMEM;
			return -1;
		}
		buff->data = tmp;
		buff_len = want;
	}

	/*
	 *	Read data up to max, or until there's no data left
	 *
	 *	Condition is a sanity check
	 */
	for (i = 0; i <= FR_CHANNEL_MAX_PACKET_LEN; i++) {
		size_t len;

		len = buff_len - buff->used;
		slen = read(fd, buff->data + buff->used, len);
		if (slen < 0) {
			if (errno == EINTR) continue;
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) return 0;	/* This is fine... */

			return -1;
		}
		/*
		 *	Zero means EOF, usually meaning the other end
		 *	of the connection went away, or, literally EOF.
		 */
		if (slen == 0) {
			/* If we read some data, hand it back */
			if (i > 0) return buff->used - had;

			/* Else other side has gone away */
			errno = EPIPE;
			return -1;
		}

		buff->used += (size_t)slen;

		/*
		 *	If we read less than a buffer's worth of data,
		 *	or enough to satisfy this channel, then return.
		 */
		if ((buff->used >= buff->expected) || ((size_t)slen < len)) break;

		/*
		 *	If we already have the biggest buffer we're
		 *	allowed, return and let the caller consume
		 *	some of the data.
		 */
		if (buff_len == max) break;

		/*
		 *	Otherwise expand the buffer, and read mode data!
		 */
		want = buff_len + FR_CHANNEL_BUFF_PRE_MAX;
		if (want > FR_CHANNEL_BUFF_PRE_MAX) want = max;

		tmp = talloc_realloc(buff, buff->data, uint8_t, want);
		if (!tmp) {
			errno = ENOMEM;
			return -1;
		}
		buff->data = tmp;		/* Only update after we know the realloc was good */
		buff_len = want;
	}
	if (!fr_cond_assert(i <= FR_CHANNEL_MAX_PACKET_LEN)) return -1;

	return buff->used - had;
}

/** Reads channel data from an fd
 *
 * This emulates SCTP and allows multiple channels (streams) to exist within a file descriptor.
 * Channels are used in radmin to separate out data into output channels (stdout, stderr etc..),
 * and to indicate the operation being performed.
 *
 * This function will drain all data for a channel.  It may be called multiple times to
 * read all data from the socket into a buffer.
 *
 * @note buff contains an expandable buffer which is managed by fr_channel_read.
 * @note Will work fine for both blocking and non-blocking fds.
 * @note May read several channels data from the socket, in which change subsequent calls
 *	will not result in read()s but will result in channel data being output.
 *
 * @param[out] out	Data available for processing.
 * @param[out] outlen	Length of data available for processing.
 * @param[out] channel	The channel number the data was received on.
 * @param[in] fd	to read channel data from.
 * @param[in] buff	tracks state of a read operation.
 * @return
 *	- #FR_CHANNEL_STATUS_FAIL	if we experienced a fatal error reading.
 *	- #FR_CHANNEL_STATUS_SUCCESS	if all data was drained for a channel.
 *	- #FR_CHANNEL_STATUS_AGAIN	expecting more data...
 */
fr_channel_status_t fr_channel_read(uint8_t const **out, size_t *outlen, fr_channel_type_t *channel,
				    int fd, fr_channel_buff_t *buff)
{
	ssize_t			slen;
	channel_header_t const	*hdr;

	*out = NULL;
	*outlen = 0;

	/*
	 *	Last call we read enough data to fill this channel
	 *
	 *	Drain that data from the buffer.
	 */
	if ((buff->used > 0) && (buff->expected > 0) && (buff->used >= buff->expected)) {
		uint8_t *tmp;

		*channel = FR_CHANNEL_UNKNOWN;
		memmove(buff->data, buff->data + buff->expected, buff->used - buff->expected);

		buff->used -= buff->expected;
		buff->expected = 0;

		if ((buff->used > FR_CHANNEL_BUFF_PRE_MIN) && (buff->used < talloc_array_length(buff->data))) {
			tmp = talloc_realloc(buff, buff->data, uint8_t, buff->used);
			if (!tmp) {
				fr_strerror_printf("Shrinking buffer failed");
				return FR_CHANNEL_STATUS_FAIL;
			}
			buff->data = tmp;
		}
	}

	/*
	 *	Check if this is a new packet
	 */
	if (buff->expected == 0) {
		/*
		 *	We may already have the next channel header...
		 */
		if (buff->used < sizeof(*hdr)) {
			slen = channel_read(fd, buff, FR_CHANNEL_MAX_PACKET_LEN - talloc_array_length(buff->data));
			if (slen < 0) {
			error:
				fr_strerror_printf("Read on socket failed: %s", fr_syserror(errno));
				return FR_CHANNEL_STATUS_FAIL;
			}
			if ((slen == 0) || (buff->used < sizeof(*hdr))) return FR_CHANNEL_STATUS_AGAIN;
		}

		/*
		 *	Figure out how much more data is needed
		 */
		hdr = (channel_header_t const *)buff->data;
		buff->channel = ntohs(hdr->channel);
		buff->expected = ntohs(hdr->length) + sizeof(*hdr);

		if ((buff->expected - sizeof(*hdr)) == 0) {
			*channel = buff->channel;
			return FR_CHANNEL_STATUS_SUCCESS;	/* Empty packet */
		}
	}
	/*
	 *	If we expected more data than we have, read more data!
	 */
	else if (buff->expected > buff->used) {
		if (buff->used < FR_CHANNEL_MAX_PACKET_LEN) {
			slen = channel_read(fd, buff, FR_CHANNEL_MAX_PACKET_LEN - talloc_array_length(buff->data));
			if (slen < 0) goto error;

			/* EAGAIN, or we still need more data */
			if ((slen == 0) || (buff->expected > buff->used)) return FR_CHANNEL_STATUS_AGAIN;
		} else {
			fr_strerror_printf("Expected data exceeds max packet size");
			return FR_CHANNEL_STATUS_FAIL;
		}
	}

	/*
	 *	We have a complete 'packet' of channel data
	 */
	if (buff->expected > sizeof(*hdr)) {
		*out = buff->data + sizeof(*hdr);
		*outlen = buff->expected - sizeof(*hdr);
	}
	*channel = buff->channel;

	return FR_CHANNEL_STATUS_SUCCESS;
}

static ssize_t lo_write(int fd, void const *inbuf, size_t buflen)
{
	size_t total;
	ssize_t r;
	uint8_t const *buffer = inbuf;

	total = buflen;

	while (total > 0) {
		r = write(fd, buffer, total);
		if (r == 0) {
			errno = EAGAIN;
			return -1;
		}

		if (r < 0) {
			if (errno == EINTR) continue;

			return -1;
		}

		buffer += r;
		total -= r;
	}

	return buflen;
}

ssize_t fr_channel_write(int fd, fr_channel_type_t channel, void const *in, size_t inlen)
{
	ssize_t r;
	channel_header_t hdr;
	uint8_t const *buffer = in;

	hdr.channel = htons(channel);
	hdr.length = htons(inlen);

	DEBUG4("Write on channel %s (%i) len %zu",
	       fr_int2str(fr_channel_type_table, channel, "<INVALID>"), channel, inlen);

	/*
	 *	Write the header
	 */
	r = lo_write(fd, &hdr, sizeof(hdr));
	if (r <= 0) return r;

	/*
	 *	Write the data directly from the buffer
	 */
	r = lo_write(fd, buffer, inlen);
	if (r <= 0) return r;

	return inlen;
}

/** Allocate a channel buffer
 *
 * @param ctx to allocate buffer in.
 * @return
 *	- a new channel buff on success.
 *	- NULL on failure.
 */
fr_channel_buff_t *fr_channel_buff_alloc(TALLOC_CTX *ctx, size_t preallocate)
{
	fr_channel_buff_t *buff;

	if (preallocate) {
		buff = talloc_pooled_object(ctx, fr_channel_buff_t, 1, preallocate);
		memset(buff, 0, sizeof(fr_channel_buff_t));
	} else {
		buff = talloc_zero(ctx, fr_channel_buff_t);
	}

	buff->data = talloc_array(buff, uint8_t, FR_CHANNEL_BUFF_PRE_MIN);
	buff->channel = FR_CHANNEL_UNKNOWN;

	return buff;
}
