// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define SOCKET_TEST_PORT 8989

typedef struct _connection_tuple
{
    uint32_t dst_ip;
    uint16_t dst_port;
    uint32_t new_dst_ip;
    uint16_t new_dst_port;
} connection_tuple_t;

typedef struct _audit_entry
{
    connection_tuple_t tuple;
    bool outbound : 1;
    bool connected : 1;
} audit_entry_t;
