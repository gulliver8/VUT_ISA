//======== Copyright (c) 2022, FIT VUT Brno, All rights reserved. ============//
//
// $NoKeywords: $flow $netflow_generator.cpp
// $Author:     Lucia Makaiová <xmakai00@stud.fit.vutbr.cz>
// $Date:       $2022-10-12
//============================================================================//
/**
 * @file        netflow_generator.cpp
 * @author      Lucia Makaiová
 *
 * @brief       Specifies function to create udp client for specified ip and port
 */

#include "netflow_generator.h"

/**
 * create udp client
 * MODIFICATED from
 * SOURCE: https://moodle.vut.cz/
 * AUTHOR: Petr Matousek
 * COPYRIGHT: (c) Petr Matousek, 2016
 */
    int client(Options options)
    {
        int sock;                        // socket descriptor
        int msg_size, i;
        struct sockaddr_in server, from; // address structures of the server and the client
        socklen_t len, fromlen;

        memset(&server,0,sizeof(server)); // erase the server structure
        server.sin_family = AF_INET;
        server.sin_addr = options.ip;
        server.sin_port = htons(options.port);        // server port (network byte order)

        if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
            printf("socket() failed\n");

        printf("* Server socket created\n");

        len = sizeof(server);
        fromlen = sizeof(from);

        printf("* Creating a connected UDP socket using connect()\n");
        // create a connected UDP socket
        if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
            printf( "connect() failed");

        return sock;
    }
