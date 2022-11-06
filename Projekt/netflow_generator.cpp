//======== Copyright (c) 2022, FIT VUT Brno, All rights reserved. ============//
//
// $NoKeywords: $flow $netflow_generator.cpp
// $Author:     Lucia Makaiová <xmakai00@stud.fit.vutbr.cz>
// $Date:       $2022-10-12
//============================================================================//
/**
 * @file        netflow_generator.h
 * @author      Lucia Makaiová
 *
 * @brief
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
        // make DNS resolution of the first parameter using gethostbyname()
       // if ((servent = gethostbyname((options.hostname).c_str())) == NULL) { // check the first parameter
        //    printf("gethostbyname() failed\n");
        //}

        // copy the first parameter to the server.sin_addr structure
        //memcpy(&server.sin_addr,servent->h_addr,servent->h_length);

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

        //send data to the server



            // obtain the local IP address and port using getsockname()
        //if (getsockname(sock,(struct sockaddr *) &from, &len) == -1)
        //      printf("getsockname() failed");
        //
        //printf("* Data sent from %s, port %d (%d) to %s, port %d (%d)\n",inet_ntoa(from.sin_addr), ntohs(from.sin_port), from.sin_port, inet_ntoa(server.sin_addr),ntohs(server.sin_port), server.sin_port);

            /* read the answer from the server
            if ((i = recv(sock,buffer, BUFFER,0)) == -1)
                printf("recv() failed");
            else if (i > 0){
                // obtain the remote IP adddress and port from the server (cf. recfrom())
                if (getpeername(sock, (struct sockaddr *)&from, &fromlen) != 0)
                    printf("getpeername() failed\n");

                printf("* UDP packet received from %s, port %d\n",inet_ntoa(from.sin_addr),ntohs(from.sin_port));
                printf("%.*s",i,buffer);                   // print the answer
            }*/

        // reading data until end-of-file (CTRL-D)


        return sock;
    }
    int client_send(char** buffer, int sock){
        int msg_size = sizeof(&buffer);
        int i = send(sock,&buffer,msg_size,0);     // send data to the server
        if (i == -1)                   // check if data was sent correctly
            printf("send() failed");
        else if (i != msg_size)
            printf("send(): buffer written partially");
        return 0;
    }
