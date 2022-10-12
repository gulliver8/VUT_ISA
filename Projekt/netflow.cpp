//======== Copyright (c) 2022, FIT VUT Brno, All rights reserved. ============//
//
// $NoKeywords: $netflow $netflow.cpp
// $Author:     Lucia Makaiová <xmakai00@stud.fit.vutbr.cz>
// $Date:       $2022-10-12
//============================================================================//
/**
 * @file        netflow.cpp
 * @author      Lucia Makaiová
 *
 * @brief
 */

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
#include <netinet/ip_icmp.h>
#include <iostream>

using namespace std;

int main(int argc, char **argv) {
    printf("Hello");
}