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

#include <pcap.h>
#include <map>
#define __FAVOR_BSD
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

#define BUFFER 1024     //buffer length

#define IPV4 0x0800
#define ARP 0x0806
#define IPV6 0x86dd
#define ICMP 1
#define TCP 6
#define UDP 17

using namespace std;

#endif //PROJEKT_FLOW_H
