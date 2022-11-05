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
                get_hostname(options);
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

void get_hostname(Options *options){
    string hostName = options->hostname;

    size_t colonPos = hostName.find(':');

    if(colonPos != string::npos)
    {
        hostName = hostName.substr(0,colonPos);
        string portPart = hostName.substr(colonPos+1);

        stringstream parser(portPart);

        int port = 0;
        if( parser >> port )
        {
            if(port >= 0 and port < 65536){
                options->port = port;
            }else{
                //TODO error
            }
        }
        else
        {
            //TODO errror- port not convertible to an integer
        }
    }
    if(inet_aton((hostName).c_str(),&options->ip) == 0){        //convert to ip
        // if address not in valid ip format
        //make DNS resolution of the first parameter using gethostbyname()
        struct hostent *servent;                        // network host entry required by gethostbyname()
        if ((servent = gethostbyname(hostName.c_str())) == NULL) {
            printf("gethostbyname() failed\n");         //invalid hostname
            exit(1);
        }
        // copy the first parameter to the server.sin_addr structure
        memcpy(&options->ip,servent->h_addr,servent->h_length);
    }
    // After processing port
}
