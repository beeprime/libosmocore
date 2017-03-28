/* (C) 2016 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ELEMENT_MSGB_MAXLEN 256

#define IP_V4_ADDR_LEN 4
#define IP_V6_ADDR_LEN 16
#define IP_PORT_LEN 2

#define CHANNEL_TYPE_ELEMENT_MAXLEN 11
#define CHANNEL_TYPE_ELEMENT_MINLEN 3
#define ENCRYPT_INFO_ELEMENT_MINLEN 1

/* Encode AoIP transport address element */
struct msgb *gsm0808_enc_aoip_trasp_addr(struct sockaddr_storage *ss)
{
	/* See also 3GPP TS 48.008 3.2.2.102 AoIP Transport Layer Address */
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	uint16_t port = 0;

	uint8_t *ptr;
	struct msgb *msg;

	OSMO_ASSERT(ss);
	OSMO_ASSERT(ss->ss_family == AF_INET || ss->ss_family == AF_INET6);

	msg = msgb_alloc(ELEMENT_MSGB_MAXLEN, "AoIP Transport Layer Address");
	if (!msg)
		return NULL;

	switch (ss->ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)ss;
		port = ntohs(sin->sin_port);
		ptr = msgb_put(msg, IP_V4_ADDR_LEN);
		memcpy(ptr, &sin->sin_addr.s_addr, IP_V4_ADDR_LEN);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)ss;
		port = ntohs(sin6->sin6_port);
		ptr = msgb_put(msg, IP_V6_ADDR_LEN);
		memcpy(ptr, sin6->sin6_addr.s6_addr, IP_V6_ADDR_LEN);
		break;
	}

	msgb_put_u16(msg, port);
	return msg;
}

/* Decode AoIP transport address element */
struct sockaddr_storage *gsm0808_dec_aoip_trasp_addr(const void *ctx,
						     struct msgb *msg)
{
	/* See also 3GPP TS 48.008 3.2.2.102 AoIP Transport Layer Address */
	struct sockaddr_storage *ss;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	uint8_t *ptr;

	if (!msg)
		return NULL;

	switch (msg->len) {

	case IP_V4_ADDR_LEN + IP_PORT_LEN:
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(msgb_get_u16(msg));
		ptr = msgb_get(msg, IP_V4_ADDR_LEN);
		memcpy(&sin.sin_addr.s_addr, ptr, IP_V4_ADDR_LEN);
		ss = talloc_zero(ctx, struct sockaddr_storage);
		if (!ss)
			return NULL;
		memcpy(ss, &sin, sizeof(sin));
		break;
	case IP_V6_ADDR_LEN + IP_PORT_LEN:
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(msgb_get_u16(msg));
		ptr = msgb_get(msg, IP_V6_ADDR_LEN);
		memcpy(sin6.sin6_addr.s6_addr, ptr, IP_V6_ADDR_LEN);
		ss = talloc_zero(ctx, struct sockaddr_storage);
		if (!ss)
			return NULL;
		memcpy(ss, &sin6, sizeof(sin6));
		break;
	default:
		/* Malformed element */
		return NULL;
		break;
	}

	return ss;
}

/* Helper function for gsm0808_enc_speech_codec()
 * and gsm0808_enc_speech_codec_list() */
static void enc_speech_codec(struct msgb *msg, struct gsm0808_speech_codec *sc)
{
	/* See also 3GPP TS 48.008 3.2.2.103 Speech Codec List */
	uint8_t header = 0;

	if (sc->fi)
		header |= (1 << 7);
	if (sc->pi)
		header |= (1 << 6);
	if (sc->pt)
		header |= (1 << 5);
	if (sc->tf)
		header |= (1 << 4);
	if (sc->type_extended) {
		header |= 0x0f;
		msgb_put_u8(msg, header);
	} else {
		OSMO_ASSERT(sc->type < 0x0f);
		header |= sc->type;
		msgb_put_u8(msg, header);
		return;
	}

	msgb_put_u8(msg, sc->type);

	if (sc->cfg_present)
		msgb_put_u16(msg, sc->cfg);
}

/* Encode Speech Codec element */
struct msgb *gsm0808_enc_speech_codec(struct gsm0808_speech_codec *sc)
{
	struct msgb *msg;

	OSMO_ASSERT(sc);

	msg = msgb_alloc(ELEMENT_MSGB_MAXLEN, "Speech Codec Element");
	if (!msg)
		return NULL;

	enc_speech_codec(msg, sc);

	return msg;
}

/* Decode Speech Codec element */
struct gsm0808_speech_codec *gsm0808_dec_speech_codec(const void *ctx,
						      struct msgb *msg)
{
	/* See also 3GPP TS 48.008 3.2.2.103 Speech Codec List */
	uint8_t header;
	struct gsm0808_speech_codec *sc;

	if (!msg)
		return NULL;

	/* Malformed elements */
	if ((msg->data[0] & 0x0F) == 0x0F && msg->len < 2)
		return NULL;
	else if ((msg->data[0] & 0x0F) != 0x0F && msg->len < 1)
		return NULL;

	header = msgb_pull_u8(msg);
	sc = talloc_zero(ctx, struct gsm0808_speech_codec);
	if (!sc)
		return NULL;

	if (header & (1 << 7))
		sc->fi = true;
	if (header & (1 << 6))
		sc->pi = true;
	if (header & (1 << 5))
		sc->pt = true;
	if (header & (1 << 4))
		sc->tf = true;

	if ((header & 0x0F) != 0x0F) {
		sc->type = (header & 0x0F);
		return sc;
	}

	sc->type = msgb_pull_u8(msg);
	sc->type_extended = true;

	if (msg->len < 2)
		return sc;

	sc->cfg = msgb_pull_u16(msg);
	sc->cfg_present = true;

	return sc;
}

/* Encode Speech Codec list */
struct msgb *gsm0808_enc_speech_codec_list(struct llist_head *scl)
{
	struct gsm0808_speech_codec *sc;
	unsigned int scl_len;
	struct msgb *msg;

	OSMO_ASSERT(scl);

	scl_len = llist_count(scl);

	/* Empty list */
	if (scl_len < 1)
		return NULL;

	msg =
	    msgb_alloc(ELEMENT_MSGB_MAXLEN * scl_len,
		       "Speech Codec Element");
	if (!msg)
		return NULL;

	llist_for_each_entry(sc, scl, list) {
		enc_speech_codec(msg, sc);
	}

	/* Prevent generating oversized TLV elements */
	if (msg->len > ELEMENT_MSGB_MAXLEN) {
		free(msg);
		return NULL;
	}

	return msg;
}

/* Decode Speech Codec list */
struct llist_head *gsm0808_dec_speech_codec_list(const void *ctx,
						 struct msgb *msg)
{
	struct llist_head *scl = NULL;
	struct gsm0808_speech_codec *sc;
	unsigned int loopcount = 0;
	unsigned int scl_len;

	if (!msg)
		return NULL;

	scl = talloc_zero(ctx, struct llist_head);
	if (!scl)
		return NULL;

	INIT_LLIST_HEAD(scl);

	while (1) {
		/* Ensure loop exit */
		if (loopcount > 255)
			break;

		sc = gsm0808_dec_speech_codec(scl, msg);
		if (sc == NULL)
			break;

		llist_add(&sc->list, scl);

		loopcount++;
	}

	scl_len = llist_count(scl);

	/* Empty list */
	if (scl_len < 1) {
		talloc_free(scl);
		return NULL;
	}

	return scl;
}

/* Encode Channel Type element */
struct msgb *gsm0808_enc_channel_type(struct gsm0808_channel_type *ct)
{
	struct msgb *msg;
	unsigned int i;
	uint8_t byte;

	OSMO_ASSERT(ct);
	OSMO_ASSERT(ct->perm_spch_len <= CHANNEL_TYPE_ELEMENT_MAXLEN-2);

	/* FIXME: Implement encoding support for Data
	 * and Speech + CTM Text Telephony */
	if ((ct->ch_indctr & 0x0f) != GSM0808_CHAN_SPEECH
	    && (ct->ch_indctr & 0x0f) != GSM0808_CHAN_SIGN)
		return NULL;

	msg = msgb_alloc(ELEMENT_MSGB_MAXLEN, "Channel Type Element");
	if (!msg)
		return NULL;

	msgb_put_u8(msg, ct->ch_indctr & 0x0f);
	msgb_put_u8(msg, ct->ch_rate_type);

	for (i = 0; i < ct->perm_spch_len; i++) {
		byte = ct->perm_spch[i];

		if (i < ct->perm_spch_len - 1)
			byte |= 0x80;
		msgb_put_u8(msg, byte);
	}

	return msg;
}

/* Decode Channel Type element */
struct gsm0808_channel_type *gsm0808_dec_channel_type(const void *ctx,
						      struct msgb *msg)
{
	struct gsm0808_channel_type *ct;
	unsigned int i;
	uint8_t byte;

	if (!msg)
		return NULL;

	/* Malformed element */
	if (msg->len < CHANNEL_TYPE_ELEMENT_MINLEN)
		return NULL;

	ct = talloc_zero(ctx, struct gsm0808_channel_type);
	if (!ct)
		return NULL;

	ct->ch_indctr = msgb_pull_u8(msg) & 0x0f;
	ct->ch_rate_type = msgb_pull_u8(msg) & 0x0f;

	for (i = 0; i < ARRAY_SIZE(ct->perm_spch); i++) {
		byte = msgb_pull_u8(msg);
		ct->perm_spch[i] = byte & 0x7f;
		if ((byte & 0x80) == 0x00)
			break;
	}
	ct->perm_spch_len = i + 1;

	return ct;
}

/* Encode Encryption Information element */
struct msgb *gsm0808_enc_encrypt_info(struct gsm0808_encrypt_info *ei)
{
	struct msgb *msg;
	unsigned int i;
	uint8_t perm_algo = 0;
	uint8_t *ptr;

	OSMO_ASSERT(ei);
	OSMO_ASSERT(ei->key_len <= ARRAY_SIZE(ei->key));
	OSMO_ASSERT(ei->perm_algo_len <= ENCRY_INFO_PERM_ALGO_MAXLEN);

	msg =
	    msgb_alloc(ELEMENT_MSGB_MAXLEN, "Encryption Information Element");
	if (!msg)
		return NULL;

	for (i = 0; i < ei->perm_algo_len; i++) {
		/* Note: gsm_08_08.h defines the permitted algorithms
		 * as an enum which ranges from 0x01 to 0x08 */
		OSMO_ASSERT(ei->perm_algo[i] != 0);
		OSMO_ASSERT(ei->perm_algo[i] <= ENCRY_INFO_PERM_ALGO_MAXLEN);
		perm_algo |= (1 << (ei->perm_algo[i] - 1));
	}

	msgb_put_u8(msg, perm_algo);
	ptr = msgb_put(msg, ei->key_len);
	memcpy(ptr, ei->key, ei->key_len);

	return msg;
}

/* Decode Encryption Information element */
struct gsm0808_encrypt_info *gsm0808_dec_encrypt_info(const void *ctx,
						      struct msgb *msg)
{
	struct gsm0808_encrypt_info *ei;
	uint8_t perm_algo;
	unsigned int i;
	uint8_t *ptr;
	unsigned int perm_algo_len = 0;

	if (!msg)
		return NULL;

	/* Malformed element */
	if (msg->len < ENCRYPT_INFO_ELEMENT_MINLEN)
		return NULL;

	ei = talloc_zero(ctx, struct gsm0808_encrypt_info);
	if (!ei)
		return NULL;

	perm_algo = msgb_pull_u8(msg);
	for (i = 0; i < ENCRY_INFO_PERM_ALGO_MAXLEN; i++) {
		if (perm_algo & (1 << i)) {
			ei->perm_algo[perm_algo_len] = i + 1;
			perm_algo_len++;
		}
	}
	ei->perm_algo_len = perm_algo_len;

	ei->key_len = msg->len;
	ptr = msgb_get(msg, msg->len);
	memcpy(ei->key, ptr, ei->key_len);

	return ei;
}
