//======== Copyright (c) 2022, FIT VUT Brno, All rights reserved. ============//
//
// $NoKeywords: $flow $arguments.cpp
// $Author:     Lucia Makaiová <xmakai00@stud.fit.vutbr.cz>
// $Date:       $2022-10-12
//============================================================================//
/**
 * @file        arguments.cpp
 * @author      Lucia Makaiová
 *
 * @brief
 */
#include<stdio.h>
#include"arguments.h"

void print_help(){
    printf("./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>] \n"
           "\n -f <file> -name of the analysed file (default = STDIN),\n"
           " -c <neflow_collector:port> -IP address, or hostname of the NetFlow collector (default = 127.0.0.1:2055),\n"
           " -a <active_timer>  - interval in seconds, after which the active flows are exported (default = 60),\n"
           " -i <seconds>       - interval in seconds, after which the inactive flows are exported (default = 10),\n"
           " -m <count>         - flow-cache size (default = 1024).\n");
    exit(0);
}

/**
 * process command line arguments
 * MODIFICATED from
 * SOURCE: https://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html
 * AUTHOR: Free Software Foundation, Inc.
 * COPYRIGHT: Copyright © 1993–2022 Free Software Foundation, Inc.
 */

void get_options(int argc, char *argv[], Options *options) {
    int input;
    while ((input = getopt(argc, argv, ":f:c:a:i:m:th")) != -1) {
        switch (input) {
            case 'h':
                print_help();
                break;
            case 'f':
                options->source.assign(optarg);
                break;
            case 'c':
                options->hostname.assign(optarg);
                break;
            case 'a':
                options->a_timer = atoi(optarg);
                if (options->a_timer == 0){
                    printf("zle");
                    exit(1);
                }
                break;
            case 'i':
                options->i_timer = atoi(optarg);
                if(options->i_timer == 0){
                    printf("zle");
                    exit(1);
                }
                break;
            case 'm':
                options->count = atoi(optarg);
                if(options->count == 0){
                    printf("zle");
                    exit(1);
                }
                break;
            case '?':
                fprintf(stderr, "invalid option: -%c\n", optopt);
                exit(1);
                break;
            case ':':
                if (optopt != 'i') {
                    fprintf(stderr, "option -%c is missing a required argument\n", optopt);
                    exit(1);
                }
            default:
                break;
        }
    }
}