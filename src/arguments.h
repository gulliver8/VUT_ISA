//======== Copyright (c) 2022, FIT VUT Brno, All rights reserved. ============//
//
// $NoKeywords: $flow $arguments.h
// $Author:     Lucia Makaiová <xmakai00@stud.fit.vutbr.cz>
// $Date:       $2022-10-12
//============================================================================//
/**
 * @file        arguments.h
 * @author      Lucia Makaiová
 *
 * @brief       Defines program options structure which stores command-line
 *              arguments and some additional information
 */


#ifndef PROJEKT_ARGUMENTS_H
#define PROJEKT_ARGUMENTS_H
#include <getopt.h>
#include <cctype>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sstream>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string>
#include <netinet/in.h>
#include <sys/socket.h>

//error macro
#define FAILURE         1
#define INVALID_INPUT   2
#define INVALID_OPTION  3
#define INVALID_HOST    4
#define INVALID_FILE    5
#define PRINT_ERR_FAILURE       fprintf(stderr, "Program execution error.")
#define PRINT_ERR_INPUT         fprintf(stderr, "Invalid input.")
#define PRINT_ERR_OPTION        fprintf(stderr, "Invalid option.")
#define PRINT_ERR_OPTION_FORMAT fprintf(stderr, "Invalid option format.")
#define PRINT_ERR_FILE          fprintf(stderr, "Invalid file.")
using namespace std;
struct Options{
    uint32_t a_timer;   //active timer value
    uint32_t i_timer;   //inactive timer value
    uint32_t count;     //number of  flows in memory
    string hostname;    //hostname and optional port
    in_addr ip;         //ip part of the hostname
    int port;           //port part of the hostname
    int sock;           //socket file descriptor after opening udp communication
    string source;      //source file
    uint32_t secs;      //system seconds (from latest packet)
    uint32_t n_secs;    //system microseconds (from latest packet)
    uint32_t flow_count;//maximum number of flows in flow cache
};

void get_options(int argc, char *argv[],Options *options);  //process command line arguments
void get_hostname(Options *options);                        //resolve host ip address and port from hostname argument
#endif //PROJEKT_ARGUMENTS_H
