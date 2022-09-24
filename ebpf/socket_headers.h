// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
// modified from https://github.com/microsoft/ebpf-for-windows/blob/main/tests/sample/cgroup_sock_addr.c

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define SOCKET_TEST_PORT 8989

typedef struct _connection_tuple
{
    unsigned int dst_ip;
    unsigned short dst_port;
    unsigned int new_dst_ip;
    unsigned short new_dst_port;
} connection_tuple_t;

