//======== Copyright (c) 2022, FIT VUT Brno, All rights reserved. ============//
//
// $NoKeywords: $flow $flow.h
// $Author:     Lucia Makaiová <xmakai00@stud.fit.vutbr.cz>
// $Date:       $2022-10-12
//============================================================================//
/**
 * @file        flow.h
 * @author      Lucia Makaiová
 *
 * @brief
 */

#ifndef PROJEKT_FLOW_H
#define PROJEKT_FLOW_H
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

#include <getopt.h>
#include <bitset>
#include <csignal>
#include <pcap.h>
#include <string>

//packet structure libraries
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <iostream>



#include "arguments.h"
#include "netflow_generator.h"
//error macro
#define FAILURE 1

#endif //PROJEKT_FLOW_H
