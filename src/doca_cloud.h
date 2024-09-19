#pragma once

#include <string>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_ether.h>

#include "doca_log.h"
#include "doca_flow.h"

#define DEFAULT_TIMEOUT_US 10000