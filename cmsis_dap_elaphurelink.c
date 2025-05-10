// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Copyright (C) 2025 by windowsair <dev@airkyi.com>
 *
 *  elaphureLink backend
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#include <stdatomic.h>
#include <string.h>
#include <helper/log.h>
#include <uv.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "cmsis_dap.h"

#ifndef MIN
# define MIN(A,B) ((A)<(B)?(A):(B))
#endif
#ifndef MAX
# define MAX(A,B) ((A)>(B)?(A):(B))
#endif

#define BUFFER_QUEUE_LEN	(MAX_PENDING_REQUESTS * 2)
#define MTU_SIZE			1500
#define HEADER_MAX_SIZE		4

#define EL_LINK_IDENTIFIER								0x8a656c70
#define EL_DAP_VERSION									0x10000
#define EL_COMMAND_HANDSHAKE							0x00000000
#define ELAPHURELINK_VENDOR_COMMAND_PREFIX				0x88
#define ELAPHURELINK_VENDOR_COMMAND_PASSTHROUGH			0x1
#define ELAPHURELINK_VENDOR_COMMAND_VENDOR_SCOPE_ENTER	0x2

#define VERSION_MAJOR(x)	(((x) >> 16) & 0xffff)
#define VERSION_MINOR(x)	(((x) >> 8) & 0xff)
#define VERSION_REVISION(x)	(((x) >> 0) & 0xff)

static char k_connect_addr[100] = "192.168.137.202";

enum elaphurelink_send_data_type {
	HANDSHAKE_DATA = 0,
	PASSTHROUGH_DATA,
};

enum context_state {
	TCP_HANDSHAKE = 0,
	ELAPHURELINK_HANDSHAKE,
	ELAPHURELINK_VENDOR_SCOPE_ENTER,
	ELAPHURELINK_VENDOR_COMMAND_HEADER,
	ELAPHURELINK_VENDOR_COMMAND_PAYLOAD,
	STATE_ERROR
};

enum buffer_status {
	BUFFER_IDLE = 0,
	BUFFER_IN_USE,
	BUFFER_SENDING,
	BUFFER_READ_DATA_AVAILABLE
};

struct elaphurelink_context;

struct elaphurelink_handshake_req {
	uint32_t el_link_identifier;
	uint32_t command;
	uint32_t el_proxy_version;
} __attribute__((packed));

struct elaphurelink_handshake_res {
	uint32_t el_link_identifier;
	uint32_t command;
	uint32_t el_dap_version;
} __attribute__((packed));

struct buffer_list {
	/* Buffer status */
	atomic_int status;
	/* Backpointer to global context */
	struct elaphurelink_context *ctx;
	uv_write_t req;
	uv_buf_t buf;
	uint8_t response_status;
	uint8_t buffer[MTU_SIZE];
};

struct elaphurelink_context {
	uv_tcp_t socket;
	uv_loop_t *loop;
	uv_async_t async_write_work;
	atomic_int async_write_request_num;
	uv_async_t async_close_work;
	uv_connect_t connect_req;
	uv_thread_t work_thread_tid;

	atomic_uint write_req_count;
	atomic_uint read_req_count;

	int last_read_error;
	int last_write_error;
	int state;

	atomic_uint write_producer_idx;
	atomic_uint write_consumer_idx;

	atomic_uint read_producer_idx;
	atomic_uint read_consumer_idx;

	uv_cond_t write_producer_cond;
	uv_mutex_t write_producer_mutex;

	uv_cond_t read_producer_cond;
	uv_mutex_t read_producer_mutex;
	uv_cond_t read_consumer_cond;
	uv_mutex_t read_consumer_mutex;

	struct buffer_list write_buffer[BUFFER_QUEUE_LEN];
	struct buffer_list read_buffer[BUFFER_QUEUE_LEN];

	struct buffer_list *cur_read_buffer_handle;
	uint8_t *cur_read_buffer;

	uint8_t byte_header_read;
	uint8_t header_buffer[HEADER_MAX_SIZE];
	uint8_t tmp_read_buffer[MTU_SIZE];
	uint8_t command_response_buffer[MTU_SIZE];
};

static void notify_read_data_available(struct buffer_list *handle)
{
	struct elaphurelink_context *ctx = handle->ctx;

	atomic_store_explicit(&handle->status, BUFFER_READ_DATA_AVAILABLE, memory_order_release);
	uv_cond_broadcast(&ctx->read_consumer_cond);
}

static void write_buffer_enqueue(struct elaphurelink_context *ctx, void *buffer, size_t len,
								 enum elaphurelink_send_data_type type)
{
	struct buffer_list *handle;
	unsigned int idx;
	uint16_t payload_len;

	idx = atomic_fetch_add_explicit(&ctx->write_producer_idx, 1, memory_order_acquire) % BUFFER_QUEUE_LEN;
	handle = &ctx->write_buffer[idx];

	uv_mutex_lock(&ctx->write_producer_mutex);
	while (atomic_load_explicit(&handle->status, memory_order_acquire) != BUFFER_IDLE)
		uv_cond_wait(&ctx->write_producer_cond, &ctx->write_producer_mutex);
	uv_mutex_unlock(&ctx->write_producer_mutex);

	if (type == HANDSHAKE_DATA) {
		handle->buf.len = len;
		memcpy(&handle->buffer[0], buffer, len);
	} else if (type == PASSTHROUGH_DATA) {
		handle->buf.len = 4 + len;
		payload_len = htons((uint16_t)len);
		handle->buffer[0] = ELAPHURELINK_VENDOR_COMMAND_PREFIX;
		handle->buffer[1] = ELAPHURELINK_VENDOR_COMMAND_PASSTHROUGH;
		memcpy(&handle->buffer[2], &payload_len, 2);
		memcpy(&handle->buffer[4], buffer, len);
	}

	atomic_store_explicit(&handle->status, BUFFER_IN_USE, memory_order_release);
	atomic_fetch_add(&ctx->async_write_request_num, 1);
}

static void write_buffer_cb(uv_write_t *req, int status)
{
	struct buffer_list *handle = (struct buffer_list *)req->data;
	struct elaphurelink_context *ctx = handle->ctx;

	if (status) {
		ctx->last_write_error = status;
		LOG_ERROR("elaphureLink: wirte callback error:%d\n", status);
	}

	atomic_store_explicit(&handle->status, BUFFER_IDLE, memory_order_release);
	uv_cond_broadcast(&ctx->write_producer_cond);
}

static void get_next_idle_read_buffer(struct elaphurelink_context *ctx, size_t len)
{
	unsigned int idx;

	idx = atomic_fetch_add_explicit(&ctx->read_producer_idx, 1, memory_order_acquire) % BUFFER_QUEUE_LEN;
	uv_mutex_lock(&ctx->read_producer_mutex);
	while (atomic_load_explicit(&ctx->read_buffer[idx].status, memory_order_acquire) != BUFFER_IDLE)
		uv_cond_wait(&ctx->read_producer_cond, &ctx->read_producer_mutex);
	uv_mutex_unlock(&ctx->read_producer_mutex);

	ctx->read_buffer[idx].buf.len = len;

	ctx->cur_read_buffer_handle = &ctx->read_buffer[idx];
	ctx->cur_read_buffer = &ctx->read_buffer[idx].buffer[0];
}

static void on_read_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
	struct elaphurelink_context *ctx = (struct elaphurelink_context *)handle->data;

	(void)suggested_size;

	buf->base = (char *)ctx->tmp_read_buffer;
	buf->len = sizeof(ctx->tmp_read_buffer);
}

static void read_vendor_command(struct elaphurelink_context *ctx, size_t nread, const uv_buf_t *buf)
{
	uint16_t *payload_length = (uint16_t *)&ctx->header_buffer[2];
	const int header_len = 4;
	char *base = buf->base;
	size_t len;

	while (nread) {
		/* header stage */
		if (ctx->byte_header_read != header_len) {
			len = MIN(nread, (size_t)(header_len - ctx->byte_header_read));
			memcpy(&ctx->header_buffer[ctx->byte_header_read], base, len);

			ctx->byte_header_read += len;
			base += len;
			nread -= len;

			if (ctx->byte_header_read == header_len) {
				/* TODO: Check header */
				*payload_length = ntohs(*payload_length);
				if (*payload_length > MTU_SIZE - HEADER_MAX_SIZE) {
					LOG_ERROR("elaphureLink: Invalid payload size:%d\n", *payload_length);
					ctx->last_read_error = UV_ENOMEM;
					goto err;
				}
				get_next_idle_read_buffer(ctx, *payload_length);
				ctx->cur_read_buffer_handle->response_status = ctx->header_buffer[1];
			} else {
				continue;
			}
		}
		/* payload stage */
		if (*payload_length) {
			len = MIN(*payload_length, nread);
			memcpy(ctx->cur_read_buffer, base, len);

			*payload_length -= len;
			ctx->cur_read_buffer += len;
			base += len;
			nread -= len;
		}

		if (*payload_length == 0) {
			notify_read_data_available(ctx->cur_read_buffer_handle);
			memset(ctx->header_buffer, 0, header_len);
			ctx->byte_header_read = 0;
			ctx->cur_read_buffer = NULL;
			ctx->cur_read_buffer_handle = NULL;
		}
	}

	return;
err:
	uv_async_send(&ctx->async_close_work);
}

static void read_handshake_data(struct elaphurelink_context *ctx, size_t nread, const uv_buf_t *buf)
{
	const int handshake_res_len = sizeof(struct elaphurelink_handshake_res);
	uv_buf_t remain_buf;
	char *base = buf->base;
	size_t len;

	if (ctx->cur_read_buffer_handle == NULL) {
		get_next_idle_read_buffer(ctx, handshake_res_len);
		ctx->cur_read_buffer_handle->status = 0;
	}

	if (ctx->byte_header_read != handshake_res_len) {
		len = MIN(nread, handshake_res_len);
		memcpy(&ctx->command_response_buffer[ctx->byte_header_read], base, len);
		ctx->byte_header_read += len;
		nread -= len;
		base += len;
	}

	if (ctx->byte_header_read == handshake_res_len) {
		memcpy(ctx->cur_read_buffer, ctx->command_response_buffer, handshake_res_len);
		notify_read_data_available(ctx->cur_read_buffer_handle);
		ctx->byte_header_read = 0;
		ctx->cur_read_buffer = NULL;
		ctx->cur_read_buffer_handle = NULL;
		ctx->state = ELAPHURELINK_VENDOR_COMMAND_HEADER;

		/* remain data process */
		if (nread) {
			remain_buf.base = base;
			remain_buf.len = nread;
			read_vendor_command(ctx, nread, &remain_buf);
		}
	}
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
	struct elaphurelink_context *ctx = (struct elaphurelink_context *)stream->data;

	if (nread > 0) {
		if (ctx->last_read_error)
			return;

		switch (ctx->state) {
		case ELAPHURELINK_HANDSHAKE:
			read_handshake_data(ctx, nread, buf);
			break;
		case ELAPHURELINK_VENDOR_COMMAND_HEADER:
		case ELAPHURELINK_VENDOR_COMMAND_PAYLOAD:
			read_vendor_command(ctx, nread, buf);
			break;
		default:
			break;
		}
	} else if (nread < 0) {
		ctx->last_read_error = nread;
		LOG_WARNING("elaphureLink read error: %s\n", uv_strerror(nread));
		if (nread == UV_EOF)
			printf("End of stream\n");

		uv_read_stop(stream);
		/* TODO:error process */
	}
}

/* Try to get data from response buffer */
static int fill_response_buffer(struct elaphurelink_context *ctx, void *buffer, uint8_t *reponse_status)
{
	unsigned int idx;
	int ret = 0;

	if (ctx->last_read_error)
		return ctx->last_read_error;

	idx = atomic_fetch_add_explicit(&ctx->read_consumer_idx, 1, memory_order_acquire) % BUFFER_QUEUE_LEN;
	uv_mutex_lock(&ctx->read_consumer_mutex);
	while (atomic_load_explicit(&ctx->read_buffer[idx].status, memory_order_acquire) != BUFFER_READ_DATA_AVAILABLE)
		uv_cond_wait(&ctx->read_consumer_cond, &ctx->read_consumer_mutex);
	uv_mutex_unlock(&ctx->read_consumer_mutex);

	ret = ctx->read_buffer[idx].buf.len;
	memcpy(buffer, ctx->read_buffer[idx].buffer, ret);
	*reponse_status = ctx->read_buffer[idx].response_status;

	atomic_store_explicit(&ctx->read_buffer[idx].status, BUFFER_IDLE, memory_order_release);
	uv_cond_broadcast(&ctx->read_producer_cond);

	return ret;
}

static void on_connect(uv_connect_t *req, int status)
{
	struct elaphurelink_context *ctx = (struct elaphurelink_context *)req->data;

	ctx->state = ELAPHURELINK_HANDSHAKE;

	if (status != 0)
		ctx->last_read_error = status;

	if (status < 0) {
		return;
	} else if (status == UV_ECANCELED) {
		return;
	}
}

static void async_write_buffer_send_work(uv_async_t *async)
{
	struct elaphurelink_context *ctx = (struct elaphurelink_context *)async->data;
	struct buffer_list *handle;
	unsigned int idx;
	int ret;

	while (atomic_load(&ctx->async_write_request_num) > 0) {
		idx = atomic_fetch_add_explicit(&ctx->write_consumer_idx, 1, memory_order_acquire) % BUFFER_QUEUE_LEN;
		handle = &ctx->write_buffer[idx];

		ret = uv_write(&handle->req, (uv_stream_t *)&ctx->socket, &handle->buf, 1, write_buffer_cb);
		if (ret)
			LOG_WARNING("Failed to write, ret:%d\n", ret);

		atomic_store_explicit(&handle->status, BUFFER_SENDING, memory_order_release);
		atomic_fetch_sub(&ctx->async_write_request_num, 1);
	}
}

static void async_close_work(uv_async_t *async)
{
	struct elaphurelink_context *ctx = (struct elaphurelink_context *)async->data;

	uv_close((uv_handle_t *)&ctx->socket, NULL);
	uv_close((uv_handle_t *)async, NULL);
	uv_close((uv_handle_t *)&ctx->async_write_work, NULL);
}

static void vendor_command_work_thread(void *arg)
{
	struct elaphurelink_context *ctx = (struct elaphurelink_context *)arg;

	uv_read_start((uv_stream_t *)&ctx->socket, on_read_alloc, on_read);
	uv_run(ctx->loop, UV_RUN_DEFAULT);
}

static int elaphurelink_handshake(struct elaphurelink_context *ctx)
{
	uint8_t scope_enter_req[4] = {ELAPHURELINK_VENDOR_COMMAND_PREFIX, ELAPHURELINK_VENDOR_COMMAND_VENDOR_SCOPE_ENTER,
								  0x0, 0x0};
	struct elaphurelink_handshake_res *handshake_res =
		(struct elaphurelink_handshake_res *)ctx->command_response_buffer;
	struct elaphurelink_handshake_req handshake_req;
	uint8_t response_status = 0;
	int ret = 0;

	handshake_req.command = htonl(EL_COMMAND_HANDSHAKE);
	handshake_req.el_link_identifier = htonl(EL_LINK_IDENTIFIER);
	handshake_req.el_proxy_version = htonl(EL_DAP_VERSION);

	write_buffer_enqueue(ctx, &handshake_req, sizeof(struct elaphurelink_handshake_req), HANDSHAKE_DATA);
	ret = uv_async_send(&ctx->async_write_work);
	if (ret)
		return ret;
	ret = fill_response_buffer(ctx, ctx->command_response_buffer, &response_status);
	if (ret < 0)
		return ret;
	if (response_status)
		return response_status;

	handshake_res->el_link_identifier = ntohl(handshake_res->el_link_identifier);
	handshake_res->command = ntohl(handshake_res->command);
	handshake_res->el_dap_version = ntohl(handshake_res->el_dap_version);

	if (handshake_res->el_link_identifier != EL_LINK_IDENTIFIER || handshake_res->command != EL_COMMAND_HANDSHAKE) {
		LOG_ERROR("Invalid elaphureLink handshake response\n");
		return -1;
	}

	if (VERSION_MAJOR(handshake_res->el_dap_version) < 1) {
		LOG_ERROR("This version of elaphureLink is not support!\n");
		return -1;
	}

	/* Scope enter command send */
	write_buffer_enqueue(ctx, scope_enter_req, sizeof(scope_enter_req), HANDSHAKE_DATA);
	ret = uv_async_send(&ctx->async_write_work);
	if (ret)
		return ret;
	ret = fill_response_buffer(ctx, ctx->command_response_buffer, &response_status);
	if (ret < 0)
		return ret;
	if (response_status)
		return response_status;

	return 0;
}

static int cmsis_dap_elaphurelink_open(struct cmsis_dap *dap, uint16_t vids[], uint16_t pids[], const char *serial)
{
	(void)vids;
	(void)pids;
	(void)serial;

	struct elaphurelink_context *ctx;
	int ret, i;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		LOG_ERROR("elaphureLink: Out of memory\n");
		return ERROR_FAIL;
	}

	dap->bdata = (struct cmsis_dap_backend_data *)ctx;
	dap->packet_buffer = ctx->command_response_buffer;
	dap->packet_size = MTU_SIZE - HEADER_MAX_SIZE;
	dap->packet_usable_size = MTU_SIZE - HEADER_MAX_SIZE;
	dap->packet_buffer_size = MTU_SIZE;
	dap->command = dap->packet_buffer;
	dap->response = dap->packet_buffer;

	for (i = 0; i < BUFFER_QUEUE_LEN; i++) {
		ctx->write_buffer[i].buf.base = (char *)ctx->write_buffer[i].buffer;
		ctx->read_buffer[i].buf.base = (char *)ctx->read_buffer[i].buffer;
		ctx->read_buffer[i].req.data = &ctx->read_buffer[i];
		ctx->write_buffer[i].req.data = &ctx->write_buffer[i];
		ctx->write_buffer[i].ctx = ctx;
		ctx->read_buffer[i].ctx = ctx;
	}

	uv_cond_init(&ctx->write_producer_cond);
	uv_cond_init(&ctx->read_producer_cond);
	uv_cond_init(&ctx->read_consumer_cond);
	uv_mutex_init(&ctx->write_producer_mutex);
	uv_mutex_init(&ctx->read_producer_mutex);
	uv_mutex_init(&ctx->read_consumer_mutex);

	ctx->loop = uv_default_loop();
	ctx->async_write_work.data = ctx;
	ret = uv_async_init(ctx->loop, &ctx->async_write_work, async_write_buffer_send_work);
	if (ret)
		goto fail;
	ctx->async_close_work.data = ctx;
	ret = uv_async_init(ctx->loop, &ctx->async_close_work, async_close_work);
	if (ret)
		goto fail;

	ctx->socket.data = ctx;
	ret = uv_tcp_init(ctx->loop, &ctx->socket);
	if (ret)
		goto fail;

	struct sockaddr_in dest;
	uv_ip4_addr(k_connect_addr, 3240, &dest);

	ctx->connect_req.data = ctx;
	uv_tcp_connect(&ctx->connect_req, &ctx->socket, (const struct sockaddr *)&dest, on_connect);

	/* Wait TCP handshake */
	while (ctx->state == TCP_HANDSHAKE)
		uv_run(ctx->loop, UV_RUN_NOWAIT);

	if (ctx->last_read_error) {
		ret = ctx->last_read_error;
		goto fail;
	}

	ret = uv_thread_create(&ctx->work_thread_tid, &vendor_command_work_thread, ctx);
	if (ret) {
		LOG_ERROR("elaphureLink: Failed to create work thread, ret:%d\n", ret);
		uv_close((uv_handle_t *)&ctx->socket, NULL);
		uv_run(ctx->loop, UV_RUN_DEFAULT);
		goto fail;
	}

	ret = elaphurelink_handshake(ctx);
	if (ret) {
		LOG_ERROR("elaphureLink: Failed to handshake, ret:%d\n", ret);
		goto fail_handshake;
	}

	printf("handshake done!\n");

	return ERROR_OK;

fail_handshake:
	uv_async_send(&ctx->async_close_work);
	uv_thread_join(&ctx->work_thread_tid);
fail:
	uv_cond_destroy(&ctx->write_producer_cond);
	uv_cond_destroy(&ctx->read_producer_cond);
	uv_cond_destroy(&ctx->read_consumer_cond);
	uv_mutex_destroy(&ctx->write_producer_mutex);
	uv_mutex_destroy(&ctx->read_producer_mutex);
	uv_mutex_destroy(&ctx->read_consumer_mutex);
	free(ctx);
	return ret;
}

static void cmsis_dap_elaphurelink_close(struct cmsis_dap *dap)
{
	struct elaphurelink_context *ctx = (struct elaphurelink_context *)dap->bdata;

	uv_async_send(&ctx->async_close_work);
	uv_thread_join(&ctx->work_thread_tid);
	uv_cond_destroy(&ctx->write_producer_cond);
	uv_cond_destroy(&ctx->read_producer_cond);
	uv_cond_destroy(&ctx->read_consumer_cond);
	uv_mutex_destroy(&ctx->write_producer_mutex);
	uv_mutex_destroy(&ctx->read_producer_mutex);
	uv_mutex_destroy(&ctx->read_consumer_mutex);
	free(ctx);
}

static int cmsis_dap_elaphurelink_read(struct cmsis_dap *dap, int transfer_timeout_ms, struct timeval *wait_timeout)
{
	(void)transfer_timeout_ms;
	(void)wait_timeout;

	struct elaphurelink_context *ctx = (struct elaphurelink_context *)dap->bdata;
	uint8_t response_status;
	int ret;

	/*
	 * Flush operation may continue reading when there is no response.
	 * Just check if there is any write request, otherwise return timeout
	 * directly.
	 */
	if (ctx->read_req_count == ctx->write_req_count)
		return ERROR_TIMEOUT_REACHED;

	ret = fill_response_buffer(ctx, dap->response, &response_status);

	atomic_fetch_add_explicit(&ctx->read_req_count, 1, memory_order_release);
	return ret;
}

static int cmsis_dap_elaphurelink_write(struct cmsis_dap *dap, int txlen, int timeout_ms)
{
	(void)timeout_ms;

	struct elaphurelink_context *ctx = (struct elaphurelink_context *)dap->bdata;
	int ret;

	if (txlen > MTU_SIZE - HEADER_MAX_SIZE) {
		LOG_ERROR("elaphureLink: txlen:%d too large!\n", txlen);
		return ERROR_FAIL;
	}

	atomic_fetch_add_explicit(&ctx->write_req_count, 1, memory_order_acquire);

	write_buffer_enqueue(ctx, dap->command, txlen, PASSTHROUGH_DATA);
	ret = uv_async_send(&ctx->async_write_work);

	return ret;
}

static int cmsis_dap_elaphurelink_alloc(struct cmsis_dap *dap, unsigned int pkt_sz)
{
	(void)dap;
	(void)pkt_sz;

	return ERROR_OK;
}

static void cmsis_dap_elaphurelink_free(struct cmsis_dap *dap)
{
	(void)dap;

	return;
}

static void cmsis_dap_elaphurelink_cancel_all(struct cmsis_dap *dap)
{
	(void)dap;
	printf("enter cancel all\n");

	return;
}

COMMAND_HANDLER(elaphure_handle_addr_command)
{
	if (CMD_ARGC == 1) {
		snprintf(k_connect_addr, sizeof(k_connect_addr), "%s", CMD_ARGV[0]);
	} else {
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	return ERROR_OK;
}

const struct command_registration cmsis_dap_elaphurelink_subcommand_handlers[] = {
	{
		.name = "addr",
		.handler = &elaphure_handle_addr_command,
		.mode = COMMAND_CONFIG,
		.help = "set address",
		.usage = "<address>",
	},
	COMMAND_REGISTRATION_DONE
};

const struct cmsis_dap_backend cmsis_dap_elaphurelink_backend = {
	.name = "elaphurelink",
	.open = cmsis_dap_elaphurelink_open,
	.close = cmsis_dap_elaphurelink_close,
	.read = cmsis_dap_elaphurelink_read,
	.write = cmsis_dap_elaphurelink_write,
	.packet_buffer_alloc = cmsis_dap_elaphurelink_alloc,
	.packet_buffer_free = cmsis_dap_elaphurelink_free,
	.cancel_all = cmsis_dap_elaphurelink_cancel_all,
};
