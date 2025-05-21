/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <uv.h>

#include "cmsis_dap.h"
#include "helper/log.h"
#include "utest.h"

#define PORT		3240
#define BUFFER_SIZE 1024

struct test_data {
	unsigned char data[1500];
	int length;
};

struct test_data k_test_data[500];

UTEST_STATE();

struct cmsis_dap k_dap = {0};
bool k_error = false;
bool k_server_done = false;

static int recv_all(int fd, uint8_t *buf, int len)
{
	int ret;

	while (len) {
		ret = recv(fd, buf, len, 0);
		if (ret <= 0)
			return ret;
		len -= ret;
		buf += ret;
	}

	return 0;
}

static int dummy_read(int fd)
{
	char buf[1500];
	int ret;

	ret = recv(fd, buf, sizeof(buf), 0);

	return ret;
}

static int normal_handshake_recv_req(int fd)
{
	unsigned char buf[1500];
	unsigned char handshake_data[] = {0x8A, 0x65, 0x6C, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
	int ret;

	ret = recv_all(fd, buf, sizeof(handshake_data));
	if (ret < 0) {
		perror("Failed to recv data from client!\n");
		goto fail;
	}

	ret = memcmp(buf, handshake_data, sizeof(handshake_data));
	if (ret) {
		perror("Handshake data not match!\n");
		goto fail;
	}

	return 0;

fail:
	k_error = true;
	return -1;
}

static int normal_handshake_send_res(int fd)
{
	unsigned char reply_data[] = {0x8A, 0x65, 0x6C, 0x70, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04};
	int ret;

	ret = send(fd, reply_data, sizeof(reply_data), 0);
	if (ret < 0) {
		perror("Failed to send data\n");
		goto fail;
	}

	return 0;

fail:
	k_error = true;
	return -1;
}

static int handshake_send_unexpected_data(int fd)
{
	unsigned char reply_data[12] = {0x00};
	int ret;

	ret = send(fd, reply_data, sizeof(reply_data), 0);
	if (ret < 0) {
		perror("Failed to send data\n");
		goto fail;
	}

	return 0;

fail:
	k_error = true;
	return -1;
}

static int handshake_send_low_version(int fd)
{
	unsigned char reply_data[] = {0x8A, 0x65, 0x6C, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	int ret;

	ret = send(fd, reply_data, sizeof(reply_data), 0);
	if (ret < 0) {
		perror("Failed to send data\n");
		goto fail;
	}

	return 0;

fail:
	k_error = true;
	return -1;
}

static int normal_enter_vendor_scope_recv_req(int fd)
{
	unsigned char buf[1500];
	unsigned char target_req[] = {0x88, 0x02, 0x00, 0x00};
	int ret;

	ret = recv_all(fd, buf, 4);
	if (ret < 0) {
		perror("Failed to recv data from client!\n");
		goto fail;
	}

	ret = memcmp(buf, target_req, sizeof(target_req));
	if (ret) {
		perror("Enter vendor scope request data not match!\n");
		goto fail;
	}

	return 0;
fail:
	k_error = true;
	return -1;
}

static int normal_enter_vendor_scope_send_res(int fd)
{
	unsigned char reply_data[] = {0x88, 0x00, 0x00, 0x00};
	int ret;

	ret = send(fd, reply_data, sizeof(reply_data), 0);
	if (ret < 0) {
		perror("Failed to send data\n");
		return -1;
	}

	return 0;
}

static int enter_vendor_scope_fail_res(int fd)
{
	unsigned char reply_data[] = {0x88, 0x1, 0x00, 0x00};
	int ret;

	ret = send(fd, reply_data, sizeof(reply_data), 0);
	if (ret < 0) {
		perror("Failed to send data\n");
		return -1;
	}

	return 0;
}

UTEST(open, normal_open)
{
	int ret;

	ret = cmsis_dap_elaphurelink_backend.open(&k_dap, NULL, NULL, NULL);
	ASSERT_EQ(ret, 0);

	cmsis_dap_elaphurelink_backend.close(&k_dap);
}

static int common_server_open(int fd)
{
	int ret;

	ret = normal_handshake_recv_req(fd);
	if (ret)
		return ret;

	ret = normal_handshake_send_res(fd);
	if (ret)
		return ret;

	ret = normal_enter_vendor_scope_recv_req(fd);
	if (ret)
		return ret;

	ret = normal_enter_vendor_scope_send_res(fd);
	if (ret)
		return ret;

	return 0;
}

int server_normal_open(int fd)
{
	int ret;

	ret = common_server_open(fd);
	if (ret)
		return ret;

	ret = dummy_read(fd);

	return 0;
}

UTEST(open, low_version_not_support)
{
	int ret;

	ret = cmsis_dap_elaphurelink_backend.open(&k_dap, NULL, NULL, NULL);
	ASSERT_NE(ret, 0);
}

int server_low_version_open(int fd)
{
	int ret;

	ret = normal_handshake_recv_req(fd);
	if (ret)
		return ret;

	ret = handshake_send_low_version(fd);
	if (ret)
		return ret;

	ret = dummy_read(fd);

	return 0;
}

UTEST(open, enter_vendor_scope_fail)
{
	int ret;

	ret = cmsis_dap_elaphurelink_backend.open(&k_dap, NULL, NULL, NULL);
	ASSERT_NE(ret, 0);
}

int server_enter_vendor_scope_fail(int fd)
{
	int ret;

	ret = normal_handshake_recv_req(fd);
	if (ret)
		return ret;

	ret = normal_handshake_send_res(fd);
	if (ret)
		return ret;

	ret = normal_enter_vendor_scope_recv_req(fd);
	if (ret)
		return ret;

	ret = enter_vendor_scope_fail_res(fd);
	if (ret)
		return ret;

	ret = dummy_read(fd);

	return 0;
}

UTEST(open, handshake_unexpected_data)
{
	int ret;

	ret = cmsis_dap_elaphurelink_backend.open(&k_dap, NULL, NULL, NULL);
	ASSERT_NE(ret, 0);
}

int server_handshake_send_unexpected_data(int fd)
{
	int ret;

	ret = normal_handshake_recv_req(fd);
	if (ret)
		return ret;

	ret = handshake_send_unexpected_data(fd);
	if (ret)
		return ret;

	ret = dummy_read(fd);

	return 0;
}

UTEST(write_only, write)
{
	unsigned char write_buf[1500];
	int len;
	int ret;

	ret = cmsis_dap_elaphurelink_backend.open(&k_dap, NULL, NULL, NULL);
	ASSERT_EQ(ret, 0);

	srand(time(NULL));

	for (int i = 0; i < 500; i++) {
		// len should not be zero
		len = rand() % 1495 + 1;

		for (int j = 0; j < len; j++) {
			write_buf[j] = i;
		}

		memcpy(k_test_data[i].data, write_buf, len);
		k_test_data[i].length = len;

		memcpy(k_dap.command, write_buf, len);
		ret = cmsis_dap_elaphurelink_backend.write(&k_dap, len, 0);

		ASSERT_EQ(ret, 0);
	}

	k_server_done = false;
	while (k_server_done) {
		usleep(1000);
	}

	cmsis_dap_elaphurelink_backend.close(&k_dap);
}

int server_write_only(int fd)
{
	int ret;
	unsigned char recv_buf[1500];
	unsigned char expected_header[2] = {0x88, 0x1};
	int i;

	ret = common_server_open(fd);
	if (ret)
		return ret;

	for (i = 0; i < 500; i++) {
		ret = recv_all(fd, recv_buf, 4);
		if (ret < 0) {
			perror("Failed to receive header from client");
			goto fail;
		}

		// check header
		if (memcmp(recv_buf, expected_header, 2) != 0) {
			printf("Header mismatch: expected 0x%02x 0x%02x, got 0x%02x 0x%02x\n", expected_header[0],
				   expected_header[1], recv_buf[0], recv_buf[1]);
			goto fail;
		}

		int data_len = (recv_buf[2] << 8) | recv_buf[3];

		// check length
		if (data_len != k_test_data[i].length) {
			printf("Data length mismatch: expected %d, got %d\n", k_test_data[i].length, data_len);
			goto fail;
		}

		// payload
		ret = recv_all(fd, recv_buf + 4, data_len);
		if (ret < 0) {
			perror("Failed to receive data from client");
			k_error = true;
			return -1;
		}

		if (memcmp(recv_buf + 4, k_test_data[i].data, data_len) != 0) {
			printf("Data content mismatch at test round %d\n", i);
			goto fail;
		}
	}

	k_server_done = true;
	return 0;

fail:
	k_server_done = true;
	k_error = true;
	return -1;
}

UTEST(read_only, read)
{
	int len;
	int ret;
	int i;

	ret = cmsis_dap_elaphurelink_backend.open(&k_dap, NULL, NULL, NULL);
	ASSERT_EQ(ret, 0);

	i = 0;
	while (i < 500) {
		len = cmsis_dap_elaphurelink_backend.read(&k_dap, 0, NULL);
		if (len == ERROR_TIMEOUT_REACHED)
			continue;
		ASSERT_EQ(len, k_test_data[i].length);

		ret = memcmp(k_dap.response, k_test_data[i].data, k_test_data[i].length);
		ASSERT_EQ(ret, 0);
		i++;
	}

	cmsis_dap_elaphurelink_backend.close(&k_dap);
}

int server_read_only(int fd)
{
	int ret;
	unsigned char send_buf[1500] = {0x88, 0x00};
	uint16_t len;
	int i;

	ret = common_server_open(fd);
	if (ret)
		return ret;

	for (i = 0; i < 500; i++) {
		len = rand() % 1495 + 1;
		send_buf[2] = len >> 8;
		send_buf[3] = len & 0xff;
		memset(&send_buf[4], i % 256, len);

		k_test_data[i].length = len;
		memset(&k_test_data[i].data[0], i, len);

		ret = send(fd, send_buf, 4 + len, 0);
		if (ret < 0) {
			printf("Failed to send data, ret:%d\n", ret);
			goto fail;
		}
	}

	ret = dummy_read(fd);

	return 0;

fail:
	k_error = true;
	return ret;
}

typedef int (*server_test_case_t)(int fd);

server_test_case_t server_case_list[] = {
	// open
	server_normal_open,
	server_low_version_open,
	server_enter_vendor_scope_fail,
	server_handshake_send_unexpected_data,
	// write
	server_write_only,
	// read
	server_read_only,
};

int server()
{
	struct sockaddr_in address;
	int addrlen = sizeof(address);
	int server_fd, new_socket;
	int i = 0;
	int ret = 0;
	int opt = 1;

	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		perror("Failed to create server socket\n");
		exit(EXIT_FAILURE);
	}

	ret = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (ret < 0) {
		perror("Failed to set server socket opt\n");
		goto clean;
	}

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);

	ret = bind(server_fd, (struct sockaddr *)&address, sizeof(address));
	if (ret < 0) {
		perror("Failed to bind server fd\n");
		goto clean;
	}

	ret = listen(server_fd, 1);
	if (ret < 0) {
		perror("Failed to listen\n");
		goto clean;
	}

	for (i = 0; i < (int)(sizeof(server_case_list) / sizeof(server_case_list[0])); i++) {
		new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
		if (new_socket < 0) {
			perror("Failed to accept\n");
			goto clean;
		}

		ret = server_case_list[i](new_socket);
		if (ret) {
			close(new_socket);
			goto clean;
		}

		close(new_socket);
	}

clean:
	close(server_fd);
	exit(ret);
}

void server_thread(void *arg)
{
	(void)arg;

	server();
}

int main(int argc, const char *const argv[])
{
	uv_thread_t tid;

	uv_thread_create(&tid, server_thread, NULL);
	sleep(1);
	return utest_main(argc, argv);
}
